// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  linux/drivers/mmc/core/sd_ops.h
 *
 *  Copyright 2006-2007 Pierre Ossman
 */

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/scatterlist.h>

#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sd.h>
#ifdef CONFIG_HONOR_SDCARD_DSM
#include <linux/mmc/dsm_sdcard.h>
#endif

#include "core.h"
#include "sd_ops.h"

int mmc_app_cmd(struct mmc_host *host, struct mmc_card *card)
{
	int err;
	struct mmc_command cmd = {};

	if (WARN_ON(card && card->host != host))
		return -EINVAL;

	cmd.opcode = MMC_APP_CMD;

	if (card) {
		cmd.arg = card->rca << 16;
		cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_AC;
	} else {
		cmd.arg = 0;
		cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_BCR;
	}

	err = mmc_wait_for_cmd(host, &cmd, 0);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(host), "mmc1"))
		dsm_sdcard_set_value(DSM_SDCARD_CMD55, cmd.resp[0]);

	if (err) {
		if (-ENOMEDIUM != err && -ETIMEDOUT != err
			&& !strcmp(mmc_hostname(host), "mmc1")) {
			dsm_sdcard_report(DSM_SDCARD_CMD55,
				DSM_SDCARD_CMD55_RESP_ERR);
			pr_err("%s:send cmd55 fail ,err=%d\n",
				mmc_hostname(host), err);
		}
		return err;
	}
#else
	if (err)
		return err;
#endif
	/* Check that card supported application commands */
	if (!mmc_host_is_spi(host) && !(cmd.resp[0] & R1_APP_CMD))
		return -EOPNOTSUPP;

	return 0;
}
EXPORT_SYMBOL_GPL(mmc_app_cmd);

static int mmc_wait_for_app_cmd(struct mmc_host *host, struct mmc_card *card,
				struct mmc_command *cmd)
{
	struct mmc_request mrq = {};
	int i, err = -EIO;

	/*
	 * We have to resend MMC_APP_CMD for each attempt so
	 * we cannot use the retries field in mmc_command.
	 */
	for (i = 0; i <= MMC_CMD_RETRIES; i++) {
		err = mmc_app_cmd(host, card);
		if (err) {
			/* no point in retrying; no APP commands allowed */
			if (mmc_host_is_spi(host)) {
				if (cmd->resp[0] & R1_SPI_ILLEGAL_COMMAND)
					break;
			}
			continue;
		}

		memset(&mrq, 0, sizeof(struct mmc_request));

		memset(cmd->resp, 0, sizeof(cmd->resp));
		cmd->retries = 0;

		mrq.cmd = cmd;
		cmd->data = NULL;

		mmc_wait_for_req(host, &mrq);

		err = cmd->error;
		if (!cmd->error)
			break;

		/* no point in retrying illegal APP commands */
		if (mmc_host_is_spi(host)) {
			if (cmd->resp[0] & R1_SPI_ILLEGAL_COMMAND)
				break;
		}
	}

	return err;
}

int mmc_app_set_bus_width(struct mmc_card *card, int width)
{
	struct mmc_command cmd = {};

	cmd.opcode = SD_APP_SET_BUS_WIDTH;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;

	switch (width) {
	case MMC_BUS_WIDTH_1:
		cmd.arg = SD_BUS_WIDTH_1;
		break;
	case MMC_BUS_WIDTH_4:
		cmd.arg = SD_BUS_WIDTH_4;
		break;
	default:
		return -EINVAL;
	}

	return mmc_wait_for_app_cmd(card->host, card, &cmd);
}

int mmc_send_app_op_cond(struct mmc_host *host, u32 ocr, u32 *rocr)
{
	struct mmc_command cmd = {};
	int i, err = 0;

	cmd.opcode = SD_APP_OP_COND;
	if (mmc_host_is_spi(host))
		cmd.arg = ocr & (1 << 30); /* SPI only defines one bit */
	else
		cmd.arg = ocr;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R3 | MMC_CMD_BCR;

	for (i = 100; i; i--) {
		err = mmc_wait_for_app_cmd(host, NULL, &cmd);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (err) {
		if (-ENOMEDIUM != err && -ETIMEDOUT != err &&
			!strncmp(mmc_hostname(host), "mmc1", sizeof("mmc1"))) {
			dsm_sdcard_set_value(DSM_SDCARD_ACMD41, cmd.resp[0]);
			dsm_sdcard_report(DSM_SDCARD_ACMD41,
				DSM_SDCARD_ACMD41_RESP_ERR);
		}
		break;
	}
#else
		if (err)
			break;
#endif
		/* if we're just probing, do a single pass */
		if (ocr == 0)
			break;

		/* otherwise wait until reset completes */
		if (mmc_host_is_spi(host)) {
			if (!(cmd.resp[0] & R1_SPI_IDLE))
				break;
		} else {
			if (cmd.resp[0] & MMC_CARD_BUSY)
				break;
		}

		err = -ETIMEDOUT;

		mmc_delay(10);
	}

	if (!i)
		pr_err("%s: card never left busy state\n", mmc_hostname(host));
#ifdef CONFIG_HONOR_SDCARD_DSM
		if (!strncmp(mmc_hostname(host), "mmc1", sizeof("mmc1")))
			dsm_sdcard_set_value(DSM_SDCARD_ACMD41, cmd.resp[0]);
#endif
	if (rocr && !mmc_host_is_spi(host))
		*rocr = cmd.resp[0];

	return err;
}

int mmc_send_if_cond(struct mmc_host *host, u32 ocr)
{
	struct mmc_command cmd = {};
	int err;
	static const u8 test_pattern = 0xAA;
	u8 result_pattern;

	/*
	 * To support SD 2.0 cards, we must always invoke SD_SEND_IF_COND
	 * before SD_APP_OP_COND. This command will harmlessly fail for
	 * SD 1.0 cards.
	 */
	cmd.opcode = SD_SEND_IF_COND;
	cmd.arg = ((ocr & 0xFF8000) != 0) << 8 | test_pattern;
	cmd.flags = MMC_RSP_SPI_R7 | MMC_RSP_R7 | MMC_CMD_BCR;

	err = mmc_wait_for_cmd(host, &cmd, 0);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(host), "mmc1"))
		dsm_sdcard_set_value(DSM_SDCARD_CMD8, cmd.resp[0]);

	if (err) {
		if (-ENOMEDIUM != err && -ETIMEDOUT != err &&
			!strcmp(mmc_hostname(host), "mmc1"))
			dsm_sdcard_report(DSM_SDCARD_CMD8,
				DSM_SDCARD_CMD8_RESP_ERR);

		return err;
	}
#else
	if (err)
		return err;
#endif
	if (mmc_host_is_spi(host))
		result_pattern = cmd.resp[1] & 0xFF;
	else
		result_pattern = cmd.resp[0] & 0xFF;

	if (result_pattern != test_pattern)
		return -EIO;

	return 0;
}

int mmc_send_relative_addr(struct mmc_host *host, unsigned int *rca)
{
	int err;
	struct mmc_command cmd = {};

	cmd.opcode = SD_SEND_RELATIVE_ADDR;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_R6 | MMC_CMD_BCR;

	err = mmc_wait_for_cmd(host, &cmd, MMC_CMD_RETRIES);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(host), "mmc1"))
		dsm_sdcard_set_value(DSM_SDCARD_CMD3, cmd.resp[0]);

	if (err) {
		if (-ENOMEDIUM != err && -ETIMEDOUT != err &&
			!strcmp(mmc_hostname(host), "mmc1"))
			dsm_sdcard_report(DSM_SDCARD_CMD3,
				DSM_SDCARD_CMD3_RESP_ERR);
		return err;
	}
#else
	if (err)
		return err;
#endif
	*rca = cmd.resp[0] >> 16;

	return 0;
}

int mmc_app_send_scr(struct mmc_card *card)
{
	int err;
	struct mmc_request mrq = {};
	struct mmc_command cmd = {};
	struct mmc_data data = {};
	struct scatterlist sg;
	__be32 *scr;

	/* NOTE: caller guarantees scr is heap-allocated */

	err = mmc_app_cmd(card->host, card);
	if (err)
		return err;

	/* dma onto stack is unsafe/nonportable, but callers to this
	 * routine normally provide temporary on-stack buffers ...
	 */
	scr = kmalloc(sizeof(card->raw_scr), GFP_KERNEL);
	if (!scr)
		return -ENOMEM;

	mrq.cmd = &cmd;
	mrq.data = &data;

	cmd.opcode = SD_APP_SEND_SCR;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = 8;
	data.blocks = 1;
	data.flags = MMC_DATA_READ;
	data.sg = &sg;
	data.sg_len = 1;

	sg_init_one(&sg, scr, 8);

	mmc_set_data_timeout(&data, card);

	mmc_wait_for_req(card->host, &mrq);

	card->raw_scr[0] = be32_to_cpu(scr[0]);
	card->raw_scr[1] = be32_to_cpu(scr[1]);

	kfree(scr);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(card->host), "mmc1")) {
		dsm_sdcard_set_value(DSM_SDCARD_ACMD51_CMDERR, cmd.error);
		dsm_sdcard_set_value(DSM_SDCARD_ACMD51_DATAERR, data.error);

		if (cmd.error || data.error)
			dsm_sdcard_report(DSM_SDCARD_ACMD51_DATAERR,
				DSM_SDCARD_ACMD51_RESP_ERR);
	}
#endif
	if (cmd.error)
		return cmd.error;
	if (data.error)
		return data.error;

	return 0;
}

int mmc_sd_switch(struct mmc_card *card, int mode, int group,
	u8 value, u8 *resp)
{
	struct mmc_request mrq = {};
	struct mmc_command cmd = {};
	struct mmc_data data = {};
	struct scatterlist sg;

	/* NOTE: caller guarantees resp is heap-allocated */

	mode = !!mode;
	value &= 0xF;

	mrq.cmd = &cmd;
	mrq.data = &data;

	cmd.opcode = SD_SWITCH;
	cmd.arg = mode << 31 | 0x00FFFFFF;
	cmd.arg &= ~(0xF << (group * 4));
	cmd.arg |= value << (group * 4);
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = 64;
	data.blocks = 1;
	data.flags = MMC_DATA_READ;
	data.sg = &sg;
	data.sg_len = 1;

	sg_init_one(&sg, resp, 64);

	mmc_set_data_timeout(&data, card);

	mmc_wait_for_req(card->host, &mrq);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(card->host), "mmc1")) {
		dsm_sdcard_set_value(DSM_SDCARD_CMD6_CMDERR, cmd.error);
		dsm_sdcard_set_value(DSM_SDCARD_CMD6_DATERR, data.error);

		if (cmd.error || data.error)
			dsm_sdcard_report(DSM_SDCARD_CMD6_DATERR,
				DSM_SDCARD_CMD6_RESP_ERR);
	}
#endif
	if (cmd.error)
		return cmd.error;
	if (data.error)
		return data.error;

	return 0;
}

int mmc_app_sd_status(struct mmc_card *card, void *ssr)
{
	int err;
	struct mmc_request mrq = {};
	struct mmc_command cmd = {};
	struct mmc_data data = {};
	struct scatterlist sg;

	/* NOTE: caller guarantees ssr is heap-allocated */

	err = mmc_app_cmd(card->host, card);
	if (err)
		return err;

	mrq.cmd = &cmd;
	mrq.data = &data;

	cmd.opcode = SD_APP_SD_STATUS;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_SPI_R2 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = 64;
	data.blocks = 1;
	data.flags = MMC_DATA_READ;
	data.sg = &sg;
	data.sg_len = 1;

	sg_init_one(&sg, ssr, 64);

	mmc_set_data_timeout(&data, card);

	mmc_wait_for_req(card->host, &mrq);
#ifdef CONFIG_HONOR_SDCARD_DSM
	if (!strcmp(mmc_hostname(card->host), "mmc1")) {
		dsm_sdcard_set_value(DSM_SDCARD_CMD13_CMDERR, cmd.error);
		dsm_sdcard_set_value(DSM_SDCARD_CMD13_DATAERR, data.error);

		if (cmd.error || data.error)
			dsm_sdcard_report(DSM_SDCARD_CMD13_DATAERR,
				DSM_SDCARD_CMD13_RESP_ERR);
	}
#endif
	if (cmd.error)
		return cmd.error;
	if (data.error)
		return data.error;

	return 0;
}
