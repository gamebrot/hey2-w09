/* 
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static_decl_rpc;

static int am_parent = 1;

#ifdef ADD_LOGIN_CONTROL
pid_t g_MainPid = 0;
#endif

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() (last_message != -1 ? smb_fn_name(last_message) : "")

extern struct auth_context *negprot_global_auth_context;
extern pstring user_socket_options;
extern SIG_ATOMIC_T got_sig_term;
extern SIG_ATOMIC_T reload_after_sighup;
static SIG_ATOMIC_T got_sig_cld;

#ifdef WITH_DFS
extern int dcelogin_atmost_once;
#endif /* WITH_DFS */

/* really we should have a top level context structure that has the
   client file descriptor as an element. That would require a major rewrite :(

   the following 2 functions are an alternative - they make the file
   descriptor private to smbd
 */
static int server_fd = -1;

#ifdef ADD_UNIX_SOCKET
static int child_smbd_sockfd = -1;

int smbd_child_fd(void)
{
	return child_smbd_sockfd;
}
#endif
int smbd_server_fd(void)
{
	return server_fd;
}

static void smbd_set_server_fd(int fd)
{
	server_fd = fd;
	client_setfd(fd);
}

struct event_context *smbd_event_context(void)
{
	static struct event_context *ctx;

	if (!ctx && !(ctx = event_context_init(NULL))) {
		smb_panic("Could not init smbd event context\n");
	}
	return ctx;
}

struct messaging_context *smbd_messaging_context(void)
{
	static struct messaging_context *ctx;

	if (!ctx && !(ctx = messaging_init(NULL, server_id_self(),
					   smbd_event_context()))) {
		smb_panic("Could not init smbd messaging context\n");
	}
	return ctx;
}

/*******************************************************************
 What to do when smb.conf is updated.
 ********************************************************************/

static void smb_conf_updated(int msg_type, struct process_id src,
			     void *buf, size_t len, void *private_data)
{
	DEBUG(10,("smb_conf_updated: Got message saying smb.conf was updated. Reloading.\n"));
	reload_services(False);
}


/*******************************************************************
 Delete a statcache entry.
 ********************************************************************/

static void smb_stat_cache_delete(int msg_type, struct process_id src,
				  void *buf, size_t len, void *private_data)
{
	const char *name = (const char *)buf;
	DEBUG(10,("smb_stat_cache_delete: delete name %s\n", name));
	stat_cache_delete(name);
}

/****************************************************************************
 Terminate signal.
****************************************************************************/

static void sig_term(void)
{
	got_sig_term = 1;
	sys_select_signal(SIGTERM);
}

/****************************************************************************
 Catch a sighup.
****************************************************************************/

static void sig_hup(int sig)
{
	reload_after_sighup = 1;
	sys_select_signal(SIGHUP);
}

/****************************************************************************
 Catch a sigcld
****************************************************************************/
static void sig_cld(int sig)
{
	got_sig_cld = 1;
	sys_select_signal(SIGCLD);
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/

static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}

/****************************************************************************
 Process a sam sync message - not sure whether to do this here or
 somewhere else.
****************************************************************************/

static void msg_sam_sync(int UNUSED(msg_type), struct process_id UNUSED(pid),
			 void *UNUSED(buf), size_t UNUSED(len),
			 void *private_data)
{
        DEBUG(10, ("** sam sync message received, ignoring\n"));
}

/****************************************************************************
 Process a sam sync replicate message - not sure whether to do this here or
 somewhere else.
****************************************************************************/

static void msg_sam_repl(int msg_type, struct process_id pid,
			 void *buf, size_t len, void *private_data)
{
        uint32 low_serial;

        if (len != sizeof(uint32))
                return;

        low_serial = *((uint32 *)buf);

        DEBUG(3, ("received sam replication message, serial = 0x%04x\n",
                  low_serial));
}

/****************************************************************************
 Open the socket communication - inetd.
****************************************************************************/

static BOOL open_sockets_inetd(void)
{
	/* Started from inetd. fd 0 is the socket. */
	/* We will abort gracefully when the client or remote system 
	   goes away */
#ifndef ADD_SECURITY_PATCH1
	smbd_set_server_fd(dup(0));
#else
	int fd = dup(0);

	if (fd < 0 || fd >= FD_SETSIZE) {
		return false;
	}

	smbd_set_server_fd(fd);
#endif
	
	/* close our standard file descriptors */
	close_low_fds(False); /* Don't close stderr */
	
	set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
	set_socket_options(smbd_server_fd(), user_socket_options);

	return True;
}

static void msg_exit_server(int msg_type, struct process_id src,
			    void *buf, size_t len, void *private_data)
{
	DEBUG(3, ("got a SHUTDOWN message\n"));
	exit_server_cleanly(NULL);
}

#ifdef DEVELOPER
static void msg_inject_fault(int msg_type, struct process_id src,
			    void *buf, size_t len, void *private_data)
{
	int sig;

	if (len != sizeof(int)) {
		
		DEBUG(0, ("Process %llu sent bogus signal injection request\n",
			(unsigned long long)src.pid));
		return;
	}

	sig = *(int *)buf;
	if (sig == -1) {
		exit_server("internal error injected");
		return;
	}

#if HAVE_STRSIGNAL
	DEBUG(0, ("Process %llu requested injection of signal %d (%s)\n",
		    (unsigned long long)src.pid, sig, strsignal(sig)));
#else
	DEBUG(0, ("Process %llu requested injection of signal %d\n",
		    (unsigned long long)src.pid, sig));
#endif

	kill(sys_getpid(), sig);
}
#endif /* DEVELOPER */

#ifdef ADD_LOGIN_CONTROL
static void msg_visitor_update(int msg_type, struct process_id src,
                void *buf, size_t len, void *private_data)
{
    VISITOR_INFO NewVisitor;

    DEBUG(10, ("[%d] msg_visitor_update enter\n", sys_getpid()));

    if(NULL == buf)
    {
        return;
    }

    memcpy(&NewVisitor, (VISITOR_INFO*)buf, sizeof(VISITOR_INFO));

    if(!am_parent)
    {
        return;
    }

    if(CheckVisitor(NewVisitor))
    {
        DEBUG(2, ("[%d] send MSG_SMB_VISITOR_ACCESS to children. name=[%s], mac=[%s]\n",
            sys_getpid(), NewVisitor.name, NewVisitor.mac));
        message_send_all(conn_tdb_ctx(),MSG_SMB_VISITOR_ACCESS, &NewVisitor, sizeof(VISITOR_INFO), False, NULL);
    }
    else
    {
        DEBUG(2, ("[%d] send MSG_SMB_VISITOR_DENY to children. name=[%s], mac=[%s]\n",
            sys_getpid(), NewVisitor.name, NewVisitor.mac));
        message_send_all(conn_tdb_ctx(),MSG_SMB_VISITOR_DENY, &NewVisitor, sizeof(VISITOR_INFO), False, NULL);
    }

    DEBUG(10, ("[%d] msg_visitor_update leave\n", sys_getpid()));
}

static void msg_visitor_access(int msg_type, struct process_id src,
                void *buf, size_t len, void *private_data)
{
    VISITOR_INFO visitor;

    DEBUG(10, ("[%d] msg_visitor_access enter\n", sys_getpid()));

    if(NULL == buf)
    {
        return;
    }

    memcpy(&visitor, (VISITOR_INFO*)buf, sizeof(VISITOR_INFO));

    if(am_parent)
    {
        return;
    }

    SetAccessVisitor(visitor);

    DEBUG(10, ("[%d] msg_visitor_access leave\n", sys_getpid()));
}

static void msg_visitor_deny(int msg_type, struct process_id src,
                void *buf, size_t len, void *private_data)
{
    VISITOR_INFO visitor;

    DEBUG(10, ("[%d] msg_visitor_deny enter\n", sys_getpid()));

    if(NULL == buf)
    {
        return;
    }

    memcpy(&visitor, (VISITOR_INFO*)buf, sizeof(VISITOR_INFO));

    if(am_parent)
    {
        return;
    }

    SetDenyVisitor(visitor);

    DEBUG(10, ("[%d] msg_visitor_deny leave\n", sys_getpid()));
}

static void msg_visitor_remove(int msg_type, struct process_id src,
                void *buf, size_t len, void *private_data)
{
    VISITOR_INFO visitor;

    DEBUG(10, ("[%d] msg_visitor_remove enter\n", sys_getpid()));

    if(NULL == buf)
    {
        return;
    }

    memcpy(&visitor, (VISITOR_INFO*)buf, sizeof(VISITOR_INFO));

    if(!am_parent)
    {
        return;
    }

    RemoveVisitor(visitor);

    DEBUG(10, ("[%d] msg_visitor_remove leave\n", sys_getpid()));
}
#endif

struct child_pid {
	struct child_pid *prev, *next;
	pid_t pid;
};

static struct child_pid *children;
static int num_children;

static void add_child_pid(pid_t pid)
{
	struct child_pid *child;

	if (lp_max_smbd_processes() == 0) {
		/* Don't bother with the child list if we don't care anyway */
		return;
	}

	child = SMB_MALLOC_P(struct child_pid);
	if (child == NULL) {
		DEBUG(0, ("Could not add child struct -- malloc failed\n"));
		return;
	}
	child->pid = pid;
	DLIST_ADD(children, child);
	num_children += 1;
}

static void remove_child_pid(pid_t pid)
{
	struct child_pid *child;
#ifndef MBB_CAN_NOT_USE
    struct server_id server;

	/*
	 * 解决samba进程异常退出后,没有清理message.tdb里的相关信息,导致文件增加,内存减小
	 * 移植自 BUG 10534: Cleanup messages.tdb record after unclean smbd shutdown.
	 * 这里不论是否开启max smbd processes限制,都建议清理
	 */
    DEBUG(3,("pid %d doesn't exist - remove it\n",(int)pid));
    server.id.pid = pid;
    messaging_cleanup_server(server);

    //DEBUG(0,("pid %d doesn't exist - lp_max_smbd_processes = %d\n",pid, lp_max_smbd_processes()));
#endif
	if (lp_max_smbd_processes() == 0) {
		/* Don't bother with the child list if we don't care anyway */
		return;
	}

	for (child = children; child != NULL; child = child->next) {
		if (child->pid == pid) {
			struct child_pid *tmp = child;
			DLIST_REMOVE(children, child);
			SAFE_FREE(tmp);
			num_children -= 1;
			return;
		}
	}

	DEBUG(0, ("Could not find child %d -- ignoring\n", (int)pid));
}

/****************************************************************************
 Have we reached the process limit ?
****************************************************************************/

static BOOL allowable_number_of_smbd_processes(void)
{
	int max_processes = lp_max_smbd_processes();

	if (!max_processes)
		return True;

	return num_children < max_processes;
}

#ifdef ADD_UNIX_SOCKET
static void *main_smbd_read_socket_thread(void *arg)
{
	char* buffer_recv = NULL;
	int sockfd;
	int buf_size;

	if (NULL == arg) {
		DEBUG(0, ("main_smbd_read_socket_thread wrong input\n"));
		LOGD("main_smbd_read_socket_thread wrong input");
		exit(1);
	}
	sockfd = *(int *)arg;
	while(1) {
		buf_size = COMMAND_TYPE_SIZE + COMMAND_LEN_SIZE;
		buffer_recv = (char *)SMB_MALLOC(buf_size);
		if(safe_socket_read(sockfd, buffer_recv, buf_size) < 0) {
			SAFE_FREE(buffer_recv);
			DEBUG(0, ("read socket failed\n"));
			LOGD("read socket failed");
			exit_server_cleanly(NULL);
		}
		if(*((uint16*)(buffer_recv)) == SMBD_CLOSE_COMMAND) {
			DEBUG(2, ("Communications is over!\n"));
			LOGD("Communications is over!");
			if (safe_socket_write(sockfd, buffer_recv, buf_size) < 0) {
				SAFE_FREE(buffer_recv);
				DEBUG(0, ("client reply to server failed\n"));
				LOGD("client reply to server failed");
				exit(1);
			}
			SAFE_FREE(buffer_recv);
			DEBUG(3, ("got a SHUTDOWN message\n"));
			LOGD("got a SHUTDOWN message");
			exit_server_cleanly(NULL);
		} else {
			SAFE_FREE(buffer_recv);
			DEBUG(3, ("got a INVALID message : %d\n", *((uint16*)(buffer_recv))));
			LOGD("got a INVALID message : %d", *((uint16*)(buffer_recv)));
		}
	}
}
#endif

/****************************************************************************
 Open the socket communication.
****************************************************************************/

bool reinit_after_fork(struct messaging_context *msg_ctx,
			struct event_context *ev_ctx,
			bool parent_longlived);

static BOOL open_sockets_smbd(BOOL is_daemon, BOOL interactive, const char *smb_ports)
{
	int num_interfaces = iface_count();
	int num_sockets = 0;
	int fd_listenset[FD_SETSIZE];
	fd_set listen_set;
	int s;
	int maxfd = 0;
	int i;
	char *ports;
#ifdef ADD_UNIX_SOCKET
	int main_smbd_sockfd;
	pthread_t read_tid;
#endif

	if (!is_daemon) {
		return open_sockets_inetd();
	}

		
#ifdef HAVE_ATEXIT
	{
		static int atexit_set;
		if(atexit_set == 0) {
			atexit_set=1;
			atexit(killkids);
		}
	}
#endif

	/* Stop zombies */
	CatchSignal(SIGCLD, sig_cld);
				
	FD_ZERO(&listen_set);

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (!smb_ports) {
		ports = lp_smb_ports();
		if (!ports || !*ports) {
			ports = smb_xstrdup(SMB_PORTS);
		} else {
			ports = smb_xstrdup(ports);
		}
	} else {
		ports = smb_xstrdup(smb_ports);
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		
		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			fstring tok;
			const char *ptr;

			if(ifip == NULL) {
				DEBUG(0,("open_sockets_smbd: interface %d has NULL IP address !\n", i));
				continue;
			}

			for (ptr=ports; next_token(&ptr, tok, " \t,", sizeof(tok)); ) {
				unsigned port = atoi(tok);
				if (port == 0 || port > 0xffff) {
					continue;
				}
				s = fd_listenset[num_sockets] = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr, True);
#ifndef ADD_SECURITY_PATCH1
				if(s == -1)
					return False;
#else
				if(s < 0 || s >= FD_SETSIZE) {
					return False;
				}
#endif

				/* ready to listen */
				set_socket_options(s,"SO_KEEPALIVE"); 
				set_socket_options(s,user_socket_options);
     
				/* Set server socket to non-blocking for the accept. */
				set_blocking(s,False); 
 
				if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
					DEBUG(0,("listen: %s\n",strerror(errno)));
					close(s);
					return False;
				}
				FD_SET(s,&listen_set);
				maxfd = MAX( maxfd, s);

				num_sockets++;
				if (num_sockets >= FD_SETSIZE) {
					DEBUG(0,("open_sockets_smbd: Too many sockets to bind to\n"));
					return False;
				}
			}
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */

		fstring tok;
		const char *ptr;

		num_interfaces = 1;
		
		for (ptr=ports; next_token(&ptr, tok, " \t,", sizeof(tok)); ) {
			unsigned port = atoi(tok);
			if (port == 0 || port > 0xffff) continue;
			/* open an incoming socket */
			s = open_socket_in(SOCK_STREAM, port, 0,
					   interpret_addr(lp_socket_address()),True);
#ifndef ADD_SECURITY_PATCH1
			if (s == -1)
				return(False);
#else
			if(s < 0 || s >= FD_SETSIZE) {
				return False;
			}
#endif
			/* ready to listen */
			set_socket_options(s,"SO_KEEPALIVE"); 
			set_socket_options(s,user_socket_options);
			
			/* Set server socket to non-blocking for the accept. */
			set_blocking(s,False); 
 
			if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
				DEBUG(0,("open_sockets_smbd: listen: %s\n",
					 strerror(errno)));
				close(s);
				return False;
			}

			fd_listenset[num_sockets] = s;
			FD_SET(s,&listen_set);
			maxfd = MAX( maxfd, s);

			num_sockets++;

			if (num_sockets >= FD_SETSIZE) {
				DEBUG(0,("open_sockets_smbd: Too many sockets to bind to\n"));
				return False;
			}
		}
	} 

	SAFE_FREE(ports);

        /* Listen to messages */

        message_register(MSG_SMB_SAM_SYNC, msg_sam_sync, NULL);
        message_register(MSG_SMB_SAM_REPL, msg_sam_repl, NULL);
        message_register(MSG_SHUTDOWN, msg_exit_server, NULL);
        message_register(MSG_SMB_FILE_RENAME, msg_file_was_renamed, NULL);
	message_register(MSG_SMB_CONF_UPDATED, smb_conf_updated, NULL); 
	message_register(MSG_SMB_STAT_CACHE_DELETE, smb_stat_cache_delete,
			 NULL);

#ifdef DEVELOPER
	message_register(MSG_SMB_INJECT_FAULT, msg_inject_fault, NULL); 
#endif
#ifdef ADD_LOGIN_CONTROL
	message_register(MSG_SMB_VISITOR_UPDATE, msg_visitor_update, NULL);
    message_register(MSG_SMB_VISITOR_ACCESS, msg_visitor_access, NULL);
    message_register(MSG_SMB_VISITOR_DENY, msg_visitor_deny, NULL);
    message_register(MSG_SMB_VISITOR_REMOVE, msg_visitor_remove, NULL);
#endif

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for a connection\n"));

#ifdef ADD_UNIX_SOCKET
	LOGD("sub smbd open and send message for socket");
	main_smbd_sockfd = open_unix_socket();
	send_unix_socket(SMBD_START_SUCCESS, main_smbd_sockfd, NULL);
	if (pthread_create(&read_tid, NULL, main_smbd_read_socket_thread, (void *)&main_smbd_sockfd) < 0) {
		DEBUG(0,("failed to create read thread\n"));
		LOGD("failed to create read thread");
		exit(1);
	}
	pthread_detach(read_tid);
#endif

	while (1) {
		fd_set lfds;
		int num;
		
		/* Free up temporary memory from the main smbd. */
		lp_TALLOC_FREE();

		/* Ensure we respond to PING and DEBUG messages from the main smbd. */
		message_dispatch();

		if (got_sig_cld) {
			pid_t pid;
			got_sig_cld = False;

			while ((pid = sys_waitpid(-1, NULL, WNOHANG)) > 0) {
				remove_child_pid(pid);
			}
		}

		memcpy((char *)&lfds, (char *)&listen_set, 
		       sizeof(listen_set));
		
		num = sys_select(maxfd+1,&lfds,NULL,NULL,NULL);
		
		if (num == -1 && errno == EINTR) {
			if (got_sig_term) {
				exit_server_cleanly(NULL);
			}

			/* check for sighup processing */
			if (reload_after_sighup) {
				change_to_root_user();
				DEBUG(1,("Reloading services after SIGHUP\n"));
				reload_services(False);
				reload_after_sighup = 0;
			}

			continue;
		}
		
		/* check if we need to reload services */
		check_reload(time(NULL));

		/* Find the sockets that are read-ready -
		   accept on these. */
		for( ; num > 0; num--) {
			struct sockaddr addr;
			socklen_t in_addrlen = sizeof(addr);
			pid_t child = 0;
#ifdef ADD_SECURITY_PATCH1
			int fd;
#endif

			s = -1;
			for(i = 0; i < num_sockets; i++) {
				if(FD_ISSET(fd_listenset[i],&lfds)) {
					s = fd_listenset[i];
					/* Clear this so we don't look
					   at it again. */
					FD_CLR(fd_listenset[i],&lfds);
					break;
				}
			}

#ifndef ADD_SECURITY_PATCH1
			smbd_set_server_fd(accept(s,&addr,&in_addrlen));
			
			if (smbd_server_fd() == -1 && errno == EINTR)
#else
			fd = accept(s,&addr,&in_addrlen);
			if (fd == -1 && errno == EINTR)
#endif
				continue;
			
#ifndef ADD_SECURITY_PATCH1
			if (smbd_server_fd() == -1) {
#else
			if (fd == -1) {
#endif
				DEBUG(0,("open_sockets_smbd: accept: %s\n",
					 strerror(errno)));
				continue;
			}
#ifdef ADD_SECURITY_PATCH1
			if (fd < 0 || fd >= FD_SETSIZE) {
				DEBUG(2,("open_sockets_smbd: bad fd %d\n",
					fd ));
				continue;
			}

			smbd_set_server_fd(fd);
#endif

			/* Ensure child is set to blocking mode */
			set_blocking(smbd_server_fd(),True);

			if (smbd_server_fd() != -1 && interactive)
				return True;
			
			if (allowable_number_of_smbd_processes() &&
			    smbd_server_fd() != -1 &&
			    ((child = sys_fork())==0)) {
				/* Child code ... */

			#ifdef ADD_UNIX_SOCKET
				close(main_smbd_sockfd);
				// modified by jjc ,todo for gaoenbo
				//pthread_cancel(main_smbd_read_socket_thread);
			#endif
				/* Stop zombies, the parent explicitly handles
				 * them, counting worker smbds. */
				CatchChild();
				
				/* close the listening socket(s) */
				for(i = 0; i < num_sockets; i++)
					close(fd_listenset[i]);
#ifndef ADD_OTHER_CHANGE
				/* close our standard file
				   descriptors */
				close_low_fds(False);
#endif
				am_parent = 0;
				
				set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
				set_socket_options(smbd_server_fd(),"TCP_KEEPCNT");
				set_socket_options(smbd_server_fd(),"TCP_KEEPIDLE");
				set_socket_options(smbd_server_fd(),"TCP_KEEPINTVL");
				set_socket_options(smbd_server_fd(),user_socket_options);
				
				/* this is needed so that we get decent entries
				   in smbstatus for port 445 connects */
				set_remote_machine_name(get_peer_addr(smbd_server_fd()),
							False);
				
				if (!reinit_after_fork(smbd_messaging_context(),
						       smbd_event_context(),
						       true)) {
					DEBUG(0, ("reinit_after_fork failed.\n"));
					smb_panic("reinit_after_fork failed.\n");
				}

				return True; 
			}
			/* The parent doesn't need this socket */
			close(smbd_server_fd()); 

			/* Sun May 6 18:56:14 2001 ackley@cs.unm.edu:
				Clear the closed fd info out of server_fd --
				and more importantly, out of client_fd in
				util_sock.c, to avoid a possible
				getpeername failure if we reopen the logs
				and use %I in the filename.
			*/

			smbd_set_server_fd(-1);

			if (child != 0) {
				add_child_pid(child);
			}

			/* Force parent to check log size after
			 * spawning child.  Fix from
			 * klausr@ITAP.Physik.Uni-Stuttgart.De.  The
			 * parent smbd will log to logserver.smb.  It
			 * writes only two messages for each child
			 * started/finished. But each child writes,
			 * say, 50 messages also in logserver.smb,
			 * begining with the debug_count of the
			 * parent, before the child opens its own log
			 * file logserver.client. In a worst case
			 * scenario the size of logserver.smb would be
			 * checked after about 50*50=2500 messages
			 * (ca. 100kb).
			 * */
			force_check_log_size();
 
		} /* end for num */
	} /* end while 1 */

/* NOTREACHED	return True; */
}

/****************************************************************************
 Reload printers
**************************************************************************/
#ifndef NOT_SUPPORT_PRINTER
void reload_printers(void)
{
	int snum;
	int n_services = lp_numservices();
	int pnum = lp_servicenumber(PRINTERS_NAME);
	const char *pname;

	pcap_cache_reload();

	/* remove stale printers */
	for (snum = 0; snum < n_services; snum++) {
		/* avoid removing PRINTERS_NAME or non-autoloaded printers */
		if (snum == pnum || !(lp_snum_ok(snum) && lp_print_ok(snum) &&
		                      lp_autoloaded(snum)))
			continue;

		pname = lp_printername(snum);
		if (!pcap_printername_ok(pname)) {
			DEBUG(3, ("removing stale printer %s\n", pname));

			if (is_printer_published(NULL, snum, NULL))
				nt_printer_publish(NULL, snum, SPOOL_DS_UNPUBLISH);
			del_a_printer(pname);
			lp_killservice(snum);
		}
	}

	load_printers();
}
#endif
/****************************************************************************
 Reload the services file.
**************************************************************************/

BOOL reload_services(BOOL test)
{
	LOGD("reload_services begin ");
	BOOL ret;
	
	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname,lp_configfile());
		if (file_exist(fname, NULL) &&
		    !strcsequal(fname, dyn_CONFIGFILE)) {
			pstrcpy(dyn_CONFIGFILE, fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	lp_killunused(conn_snum_used);

	ret = lp_load(dyn_CONFIGFILE, False, False, True, True);

#ifndef NOT_SUPPORT_PRINTER
	reload_printers();
#endif

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(True);

	reopen_logs();

	load_interfaces();

	if (smbd_server_fd() != -1) {      
		set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
		set_socket_options(smbd_server_fd(),"TCP_KEEPCNT");
		set_socket_options(smbd_server_fd(),"TCP_KEEPIDLE");
		set_socket_options(smbd_server_fd(),"TCP_KEEPINTVL");
		set_socket_options(smbd_server_fd(), user_socket_options);
	}

	mangle_reset_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,0,True);

	LOGD("reload_services ok");
	return(ret);
}

/****************************************************************************
 Exit the server.
****************************************************************************/

/* Reasons for shutting down a server process. */
enum server_exit_reason { SERVER_EXIT_NORMAL, SERVER_EXIT_ABNORMAL };

static void exit_server_common(enum server_exit_reason how,
	const char *const reason) NORETURN_ATTRIBUTE;

static void exit_server_common(enum server_exit_reason how,
	const char *const reason)
{
	static int firsttime=1;

#ifdef ADD_LOGIN_CONTROL
	if(am_parent)
    {
       DestroyVisitorLink();
    }
#endif

	if (!firsttime)
		exit(0);
	firsttime = 0;

	change_to_root_user();

	if (negprot_global_auth_context) {
		(negprot_global_auth_context->free)(&negprot_global_auth_context);
	}

	conn_close_all();

	invalidate_all_vuids();

#ifndef NOT_SUPPORT_PRINTER
	print_notify_send_messages(3); /* 3 second timeout. */
#endif

	/* delete our entry in the connections database. */
	yield_connection(NULL,"");

	respond_to_all_remaining_local_messages();

#ifdef WITH_DFS
	if (dcelogin_atmost_once) {
		dfs_unlogin();
	}
#endif

	locking_end();

#ifndef NOT_SUPPORT_PRINTER
	printing_end();
#endif

	if (how != SERVER_EXIT_NORMAL) {
		int oldlevel = DEBUGLEVEL;
		char *last_inbuf = get_InBuffer();

		DEBUGLEVEL = 10;

		DEBUGSEP(0);
		LOGD("[samba] Abnormal server exit: %s",reason ? reason : "no explanation provided");
		DEBUG(0,("Abnormal server exit: %s\n",
			reason ? reason : "no explanation provided"));
		DEBUGSEP(0);

		log_stack_trace();
		if (last_inbuf) {
			LOGD("[samba] Last message was %s",LAST_MESSAGE());
			DEBUG(0,("Last message was %s\n", LAST_MESSAGE()));
			show_msg(last_inbuf);
		}

		DEBUGLEVEL = oldlevel;
		dump_core();

	} else {
		LOGD("[smbd] Server exit (%s)",(reason ? reason : "normal exit"));
		DEBUG(3,("Server exit (%s)\n",
			(reason ? reason : "normal exit")));
	}

	exit(0);
}

void exit_server(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_ABNORMAL, explanation);
}

void exit_server_cleanly(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_NORMAL, explanation);
}

void exit_server_fault(void)
{
	exit_server("critical server fault");
}

/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/

static BOOL init_structs(void )
{
	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */

	if (!init_names())
		return False;

	conn_init();

	file_init();

	/* for RPC pipes */
	init_rpc_pipe_hnd();

	init_dptrs();

	secrets_init();

	return True;
}

/****************************************************************************
 main program.
****************************************************************************/

/* Declare prototype for build_options() to avoid having to run it through
   mkproto.h.  Mixing $(builddir) and $(srcdir) source files in the current
   prototype generation system is too complicated. */

extern void build_options(BOOL screen);

 int main(int argc,const char *argv[])
{
	LOGD(" smbd is starting");
	/* shall I run as a daemon */
	static BOOL is_daemon = False;
	static BOOL interactive = False;
	static BOOL Fork = False;
	static BOOL no_process_group = False;
	static BOOL log_stdout = False;
	static char *ports = NULL;
	static char *profile_level = NULL;
	int opt;
#ifdef NOT_HAVE_POPT
	int ch;
#else
	poptContext pc;

	struct poptOption long_options[] = {
	POPT_AUTOHELP
	{"daemon", 'D', POPT_ARG_VAL, &is_daemon, True, "Become a daemon (default)" },
	{"interactive", 'i', POPT_ARG_VAL, &interactive, True, "Run interactive (not a daemon)"},
	{"foreground", 'F', POPT_ARG_VAL, &Fork, False, "Run daemon in foreground (for daemontools, etc.)" },
	{"no-process-group", '\0', POPT_ARG_VAL, &no_process_group, True, "Don't create a new process group" },
	{"log-stdout", 'S', POPT_ARG_VAL, &log_stdout, True, "Log to stdout" },
	{"build-options", 'b', POPT_ARG_NONE, NULL, 'b', "Print build options" },
	{"port", 'p', POPT_ARG_STRING, &ports, 0, "Listen on the specified ports"},
	{"profiling-level", 'P', POPT_ARG_STRING, &profile_level, 0, "Set profiling level","PROFILE_LEVEL"},
	POPT_COMMON_SAMBA
	POPT_COMMON_DYNCONFIG
	POPT_TABLEEND
	};
#endif

	load_case_tables();

	TimeInit();

#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

#ifdef NOT_HAVE_POPT
	while ((ch = getopt(argc, argv, "D")) != -1) {
		switch(ch) {
		case 'D':
			is_daemon = true;
			break;
		default:
			printf("Run only in format : smbd -D\n");
			exit(1);
		}
	}
#else
	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case 'b':
			build_options(True); /* Display output to screen as well as debug */ 
			exit(0);
			break;
		}
	}

	poptFreeContext(pc);
#endif

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	sec_init();

	set_remote_machine_name("smbd", False);

#ifndef NOT_HAVE_POPT
	if (interactive) {
		Fork = False;
		log_stdout = True;
	}

	if (interactive && (DEBUGLEVEL >= 9)) {
		talloc_enable_leak_report();
	}

	if (log_stdout && Fork) {
		DEBUG(0,("ERROR: Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n"));
		exit(1);
	}
#endif

	setup_logging(argv[0],log_stdout);

	/* we want to re-seed early to prevent time delays causing
           client problems at a later date. (tridge) */
	generate_random_buffer(NULL, 0);

#ifndef NON_ROOT_START
	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */

	gain_root_privilege();
	gain_root_group_privilege();
#endif

	fault_setup((void (*)(void *))exit_server_fault);
	dump_core_setup("smbd");

	CatchSignal(SIGTERM , SIGNAL_CAST sig_term);
	CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
	
	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	init_sec_ctx();

	reopen_logs();

	LOGD("smbd version %s started.",SAMBA_VERSION_STRING);
	DEBUG(0,( "smbd version %s started.\n", SAMBA_VERSION_STRING));
	DEBUGADD( 0, ( "%s\n", COPYRIGHT_STARTUP_MESSAGE ) );

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	/* Output the build options to the debug log */ 
	build_options(False);

	if (sizeof(uint16) < 2 || sizeof(uint32) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	/*
	 * Do this before reload_services.
	 */

	if (!reload_services(False))
		return(-1);	

	init_structs();

#ifdef WITH_PROFILE
	if (!profile_setup(False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}
	if (profile_level != NULL) {
		int pl = atoi(profile_level);
		struct process_id src;

		DEBUG(1, ("setting profiling level: %s\n",profile_level));
		src.pid = getpid();
		set_profile_level(pl, src);
	}
#endif

	DEBUG(3,( "loaded services\n"));

	if (!is_daemon && !is_a_socket(0)) {
		if (!interactive)
			DEBUG(0,("standard input is not a socket, assuming -D option\n"));

		/*
		 * Setting is_daemon here prevents us from eventually calling
		 * the open_sockets_inetd()
		 */

		is_daemon = True;
	}

	if (is_daemon && !interactive) {
		DEBUG( 3, ( "Becoming a daemon.\n" ) );
		become_daemon(Fork, no_process_group);
	}

#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive && !no_process_group)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lockdir(), NULL))
		mkdir(lp_lockdir(), 0755);

	if (is_daemon)
		pidfile_create("smbd");

	/* Setup all the TDB's - including CLEAR_IF_FIRST tdb's. */
	if (!message_init())
		exit(1);

	/* Initialise the password backed before the global_sam_sid
	   to ensure that we fetch from ldap before we make a domain sid up */

	if(!initialize_password_db(False))
		exit(1);

	if (!secrets_init()) {
		LOGD("[smbd] ERROR: smbd can not open secrets.tdb");
		DEBUG(0, ("ERROR: smbd can not open secrets.tdb\n"));
		exit(1);
	}

	if(!get_global_sam_sid()) {
		LOGD("[smbd] ERROR: Samba cannot create a SAM SID.");
		DEBUG(0,("ERROR: Samba cannot create a SAM SID.\n"));
		exit(1);
	}

	if (!session_init())
		exit(1);

	if (conn_tdb_ctx() == NULL)
		exit(1);

	if (!locking_init(0))
		exit(1);

	namecache_enable();

	if (!init_registry())
		exit(1);

#if 0
	if (!init_svcctl_db())
                exit(1);
#endif

#ifndef NOT_SUPPORT_PRINTER
	if (!print_backend_init())
		exit(1);
#endif

	if (!init_guest_info()) {
		DEBUG(0,("ERROR: failed to setup guest info.\n"));
		return -1;
	}

	/* Setup the main smbd so that we can get messages. */
	/* don't worry about general printing messages here */

	claim_connection(NULL,"",0,True,FLAG_MSG_GENERAL|FLAG_MSG_SMBD);

#ifndef NON_ROOT_START
	/* only start the background queue daemon if we are 
	   running as a daemon -- bad things will happen if
	   smbd is launched via inetd and we fork a copy of 
	   ourselves here */

	if ( is_daemon && !interactive )
		start_background_queue(); 
#endif

	/* Always attempt to initialize DMAPI. We will only use it later if
	 * lp_dmapi_support is set on the share, but we need a single global
	 * session to work with.
	 */
	dmapi_init_session();

#ifdef ADD_LOGIN_CONTROL
	/* Get the main pid of smbd */
    g_MainPid = sys_getpid();
#endif

	if (!open_sockets_smbd(is_daemon, interactive, ports))
		exit(1);

#ifdef ADD_LOGIN_CONTROL
	/* Set parent pid to children */
    SetParentPid(g_MainPid);
#endif

	/*
	 * everything after this point is run after the fork()
	 */ 

	static_init_rpc;

	init_modules();

	/* Possibly reload the services file. Only worth doing in
	 * daemon mode. In inetd mode, we know we only just loaded this.
	 */
	if (is_daemon) {
		reload_services(True);
	}

	if (!init_account_policy()) {
		DEBUG(0,("Could not open account policy tdb.\n"));
		exit(1);
	}

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) != 0) {
			DEBUG(0,("Failed to change root to %s\n", lp_rootdir()));
			exit(1);
		}
		if (chdir("/") == -1) {
			DEBUG(0,("Failed to chdir to / on chroot to %s\n", lp_rootdir()));
			exit(1);
		}
		DEBUG(0,("Changed root to %s\n", lp_rootdir()));
	}

	/* Setup oplocks */
	if (!init_oplocks())
		exit(1);
	
	/* Setup aio signal handler. */
	initialize_async_io_handler();

	/* register our message handlers */
	message_register(MSG_SMB_FORCE_TDIS, msg_force_tdis, NULL);

#ifdef ADD_UNIX_SOCKET
    LOGD("smbd open and send message for socket");
	child_smbd_sockfd = open_unix_socket();
	send_unix_socket(DEVICE_CONNECTED, child_smbd_sockfd, NULL);
#endif

	smbd_process();

#ifdef ADD_UNIX_SOCKET
	send_unix_socket(DEVICE_DISCONNECTED, child_smbd_sockfd, NULL);
	close(child_smbd_sockfd);
#endif

	namecache_shutdown();

	exit_server_cleanly(NULL);
	return(0);
}
