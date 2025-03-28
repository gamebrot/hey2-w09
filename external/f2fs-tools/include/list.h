#ifndef _LIST_H_
#define _LIST_H_

#define POISON_POINTER_DELTA 0
#define LIST_POISON1  ((void *) (0x00100100 + POISON_POINTER_DELTA))
#define LIST_POISON2  ((void *) (0x00200200 + POISON_POINTER_DELTA))

#if !defined(offsetof)
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
		struct list_head *prev,
		struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void list_move_tail(struct list_head *list,
                                  struct list_head *head)
{
	__list_del_entry(list);
	list_add_tail(list, head);
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
			pos = n, n = pos->next)
#define list_for_each_entry(pos, head, member)                          \
	/*lint -save -e529 -e532 -e666 -e564*/ \
	for (pos = list_entry((head)->next, typeof(*pos), member);      \
			&pos->member != (head);    \
			pos = list_entry(pos->member.next, typeof(*pos), member)) \
	/*lint -restore*/
#define list_for_each_entry_safe(pos, n, head, member)                  \
	/*lint -save -e529 -e532 -e666 -e564*/ \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
			n = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head);                                    \
			pos = n, n = list_entry(n->member.next, typeof(*n), member)) \
	/*lint -restore*/

#define list_first_entry(ptr, type, member) \
	/*lint -save -e529 -e532 -e666*/ \
	list_entry((ptr)->next, type, member) \
	/*lint -restore*/

#define list_next_entry(pos, member)					\
		/*lint -save -e529 -e532 -e666*/ \
		list_entry((pos)->member.next, typeof(*(pos)), member) \
		/*lint -restore*/

#endif


