/*
 *  s5bd engine
 * 
 *  IO engine using S5's libs5bd to test S5 Block Devices.
 */

#include "../../../S5bd/include/libs5bd.h"
#include "../../../S5manager/include/libs5manager.h"
#include "../fio.h"

//#define DEBUG

struct fio_s5bd_iou {
	struct io_u *io_u;
	int io_seen;
	int io_complete;
};

struct s5bd_data {
	//rados_t cluster;
	s5_ioctx_t ictx;
	s5_volume_t image;
	struct io_u **aio_events;
	struct io_u **sort_events;
};

struct s5bd_options {
	void *pad;
	char *volume_name;
	char *tenant_name;
	char *tenant_password;
	char *config_file;
	int  busy_poll;
};

static struct fio_option options[] = {
	{
		.name		= "volume",
		.lname		= "s5bd engine volume",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Volume name for S5BD engine",
		.off1		= offsetof(struct s5bd_options, volume_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_S5BD,
	},
	{
		.name		= "tenant",
		.lname		= "s5bd engine tenant",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Tenant name fr S5BD engine",
		.off1		= offsetof(struct s5bd_options, tenant_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_S5BD,
	},
	{
		.name		= "tenant_password",
		.lname		= "s5bd engine tenant password",
		.type		= FIO_OPT_STR_STORE,
		.help 		= "Tenant password for S5BD engine",
		.off1       = offsetof(struct s5bd_options, tenant_password),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_S5BD,
	},
	{   
        .name       = "config_file",
        .lname      = "s5 configure file",
        .type       = FIO_OPT_STR_STORE,
        .help       = "The configure file of S5 for the S5BD engine",
        .off1       = offsetof(struct s5bd_options, config_file),
        .category   = FIO_OPT_C_ENGINE,
        .group      = FIO_OPT_G_S5BD,
    },  
	{
		.name		= "busy_poll",
		.lname		= "Busy poll",
		.type		= FIO_OPT_BOOL,
		.help		= "Busy poll for completions instead of sleeping",
		.off1		= offsetof(struct s5bd_options, busy_poll),
		.def		= "0",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_S5BD,
	},
	{
		.name = NULL,
	},
};

static int _fio_setup_s5bd_data(struct thread_data *td, 
                                struct s5bd_data **s5bd_data_ptr)
{
    struct s5bd_data *s5bd;

    if (td->io_ops->data)
        return 0;

    s5bd = calloc(1, sizeof(struct s5bd_data));
    if (!s5bd)
        goto failed;

    s5bd->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
    if (!s5bd->aio_events)
        goto failed;

    s5bd->sort_events = calloc(td->o.iodepth, sizeof(struct io_u *));
    if (!s5bd->sort_events)
        goto failed;

	*s5bd_data_ptr = s5bd;
    return 0;

failed:
    if (s5bd)
        free(s5bd);
    return 1;

}

static int _fio_s5bd_connect(struct thread_data *td)
{
    struct s5bd_data *s5bd = td->io_ops->data;
    struct s5bd_options *o = td->eo;
    int r;

	s5_create_ioctx(o->tenant_name, o->tenant_password, o->config_file, &(s5bd->ictx));

    r = s5_open_volume(s5bd->ictx, o->tenant_name, o->volume_name, NULL, &(s5bd->image));
    
    if(r < 0)
    {   
        log_err("s5bd open src volume[%s]  failed! err[%d]", o->volume_name, r); 
    }   
    return r;
}

static void _fio_s5bd_disconnect(struct s5bd_data *s5bd)
{
	if (!s5bd)
		return;

	/* shutdown everything */
	if (s5bd->image) {
		s5_close_volume(&(s5bd->image));
		s5bd->image = NULL;
	}
}

static void _fio_s5bd_finish_aiocb(void *data, uint64_t res_len)
{
	struct fio_s5bd_iou *fri = data;
	struct io_u *io_u = fri->io_u;

	fri->io_complete = 1;
	
	if (res_len <= 0) {
		io_u->error = EIO;
		io_u->resid = io_u->xfer_buflen;
	} else {
		#ifdef DEBUG
		printf("success\n");	
		fflush(stdout);	
		#endif
		io_u->error = 0;
	}
}

static struct io_u *fio_s5bd_event(struct thread_data *td, int event)
{
    struct s5bd_data *s5bd = td->io_ops->data;

    return s5bd->aio_events[event];
}

static inline int fri_check_complete(struct s5bd_data *s5bd, struct io_u *io_u,
                     unsigned int *events)
{
    struct fio_s5bd_iou *fri = io_u->engine_data;

    if (fri->io_complete) {
        fri->io_seen = 1;
        s5bd->aio_events[*events] = io_u;
        (*events)++;

        return 1;
    }

    return 0;
}

static inline int s5bd_io_u_seen(struct io_u *io_u)
{
    struct fio_s5bd_iou *fri = io_u->engine_data;

    return fri->io_seen;
}

static int s5bd_io_u_cmp(const void *p1, const void *p2)
{
    const struct io_u **a = (const struct io_u **) p1; 
    const struct io_u **b = (const struct io_u **) p2; 
    uint64_t at, bt; 

    at = utime_since_now(&(*a)->start_time);
    bt = utime_since_now(&(*b)->start_time);

    if (at < bt) 
        return -1; 
    else if (at == bt) 
        return 0;
    else
        return 1;
}

static int s5bd_iter_events(struct thread_data *td, unsigned int *events,
			   				unsigned int min_evts, int wait)
{
	struct s5bd_data *s5bd = td->io_ops->data;
	unsigned int this_events = 0;
	struct io_u *io_u;
	int i, sidx;

	sidx = 0;
	io_u_qiter(&td->io_u_all, io_u, i) {
		if (!(io_u->flags & IO_U_F_FLIGHT))
			continue;
		if (s5bd_io_u_seen(io_u))
			continue;

		if (fri_check_complete(s5bd, io_u, events))
			this_events++;
		else if (wait)
			s5bd->sort_events[sidx++] = io_u;
	}

	if (!wait || !sidx)
		return this_events;

	/*
 	 * 	Sort events, oldest issue first, then wait on as many as we
 	 *  need in order of age. If we have enough events, stop waiting,
 	 *  and just check if any of the older ones are done.
 	 */
	if (sidx > 1)
		qsort(s5bd->sort_events, sidx, sizeof(struct io_u *), s5bd_io_u_cmp);

	for (i = 0; i < sidx; i++) {
		io_u = s5bd->sort_events[i];

		if (fri_check_complete(s5bd, io_u, events)) {
			this_events++;
			continue;
		}

		/*
 		 * Stop waiting when we have enough, but continue checking
 		 * all pending IOs if they are complete.
 		 */
		if (*events >= min_evts)
			continue;

		if (fri_check_complete(s5bd, io_u, events))
			this_events++;
	}

	return this_events;
}

static int fio_s5bd_getevents(struct thread_data *td, unsigned int min,
			     unsigned int max, const struct timespec *t)
{
	unsigned int this_events, events = 0;
	struct s5bd_options *o = td->eo;
	int wait = 0;
	#ifdef DEBUG
	printf("before events\n");
	fflush(stdout);
	#endif 
	do {
		this_events = s5bd_iter_events(td, &events, min, wait);

		if (events >= min)
			break;
		if (this_events)
			continue;

		if (!o->busy_poll)
			wait = 1;
		else
			nop;
	} while (1);
	#ifdef DEBUG
	printf("after events\n");
	fflush(stdout);
	#endif
	return events;
}

static int fio_s5bd_queue(struct thread_data *td, struct io_u *io_u)
{
	struct s5bd_data *s5bd = td->io_ops->data;
	struct fio_s5bd_iou *fri = io_u->engine_data;
	int r = -1;
	struct timeval task_start;
	struct timeval task_end;
	float timeuse = 0;
	unsigned int read_retry_cnt = 0;
	unsigned int write_retry_cnt = 0;
	#ifdef DEBUG
	printf("before queue\n");
	fflush(stdout);
	#endif
	gettimeofday(&task_start, NULL);

//	printf("counter=%lld\n", counter++);

	fio_ro_check(td, io_u);

	fri->io_seen = 0;
	fri->io_complete = 0;

RETRY:	
	if (io_u->ddir == DDIR_WRITE) {
		//printf("io offset=%d, len=%d\n", io_u->offset, io_u->xfer_buflen);
		fflush(stdout);
		r = s5_aio_write_volume(s5bd->image, io_u->offset, io_u->xfer_buflen,
					 io_u->xfer_buf, _fio_s5bd_finish_aiocb, fri);
		if (r < 0) {
			if(r == -EAGAIN)
			{
				if (++write_retry_cnt >= 6)
				{
					printf("AIO write  got EAGAIN, sleep %d*1ms.\n", write_retry_cnt);
					write_retry_cnt = 0;
				}

				usleep(1000); 
				goto RETRY;
			}
			goto failed_comp;
		}

	} else if (io_u->ddir == DDIR_READ) {
		r = s5_aio_read_volume(s5bd->image, io_u->offset, io_u->xfer_buflen,
					io_u->xfer_buf, _fio_s5bd_finish_aiocb, fri);

		if (r < 0) {
			if(r == -EAGAIN)
			{
				if (++read_retry_cnt >= 6)
				{
					printf("AIO read got EAGAIN, sleep %d*1ms.\n", read_retry_cnt);
					read_retry_cnt = 0;
				}
				usleep(1000); 
				goto RETRY;
			}
			goto failed_comp;
		}
	} else {
		dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
		       io_u->ddir);
		goto failed_comp;
	}
	gettimeofday(&task_end, NULL);
	timeuse = (task_end.tv_sec - task_start.tv_sec) * 1000000
                  + (task_end.tv_usec - task_start.tv_usec);
	#ifdef DEBUG
	printf("after queue\n");
	fflush(stdout);
	#endif
	//printf("time_use=%f\n", timeuse);
	return FIO_Q_QUEUED;
failed_comp:
	printf("cmpare\n");
	printf("failed\n");
	io_u->error = r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static int fio_s5bd_init(struct thread_data *td)
{
	int r;

	r = _fio_s5bd_connect(td);
	if (r) {
		log_err("fio_s5bd_connect failed, return code: %d .\n", r);
		goto failed;
	}

	return 0;

failed:
	return 1;
}

static void fio_s5bd_cleanup(struct thread_data *td) 
{
    struct s5bd_data *s5bd = td->io_ops->data;

    if (s5bd) {
        _fio_s5bd_disconnect(s5bd);
        free(s5bd->aio_events);
        free(s5bd->sort_events);
        free(s5bd);
    }   
}

static int fio_s5bd_get_info(struct thread_data * td, s5_volume_info_t* info)
{
    struct s5bd_data *s5bd = td->io_ops->data;
    struct s5bd_options *o = td->eo;

	s5_create_ioctx(o->tenant_name, o->tenant_password, o->config_file, &(s5bd->ictx));
	return s5_stat_volume(s5bd->ictx, o->tenant_name, o->volume_name, info);
}

static int fio_s5bd_setup(struct thread_data *td)
{
    s5_volume_info_t info;
    struct fio_file *f; 
    struct s5bd_data *s5bd = NULL;
    int r;

    /* allocate engine specific structure to deal with libs5bd. */
    r = _fio_setup_s5bd_data(td, &s5bd);
    if (r) {
        log_err("fio_setup_s5bd_data failed.\n");
        goto cleanup;
    } 
	td->io_ops->data = s5bd;

    /* libs5bd does not allow us to run first in the main thread and later
     * in a fork child. It needs to be the same process context all the
     * time. 
     */
    td->o.use_thread = 1;

    /* get size of the S5 block device */
    r = fio_s5bd_get_info(td, &info);
    if (r < 0) {
        log_err("Failed to get volume size.\n");
        goto cleanup;
    }

	dprint(FD_IO, "s5bd-engine: image size: %lu\n", info.size);

    /* taken from "net" engine. Pretend we deal with files,
     * even if we do not have any ideas about files.
     * The size of the S5BD is set instead of a artificial file.
     */
    if (!td->files_index) {
        add_file(td, td->o.filename ? : "s5bd", 0, 0);
        td->o.nr_files = td->o.nr_files ? : 1;
        td->o.open_files++;
    }
    f = td->files[0];
    f->real_file_size = info.size;

    return 0;

cleanup:
    fio_s5bd_cleanup(td);
    return r;
}

static int fio_s5bd_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_s5bd_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void fio_s5bd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_s5bd_iou *fri = io_u->engine_data;

	if (fri) {
		io_u->engine_data = NULL;
		free(fri);
	}
}

static int fio_s5bd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_s5bd_iou *fri;

	fri = calloc(1, sizeof(*fri));
	fri->io_u = io_u;
	io_u->engine_data = fri;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "s5bd",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_s5bd_setup,
	.init			= fio_s5bd_init,
	.queue			= fio_s5bd_queue,
	.getevents		= fio_s5bd_getevents,
	.event			= fio_s5bd_event,
	.cleanup		= fio_s5bd_cleanup,
	.open_file		= fio_s5bd_open,
	.invalidate		= fio_s5bd_invalidate,
	.options		= options,
	.io_u_init		= fio_s5bd_io_u_init,
	.io_u_free		= fio_s5bd_io_u_free,
	.option_struct_size	= sizeof(struct s5bd_options),
};

static void fio_init fio_s5bd_register(void)
{
      register_ioengine(&ioengine);
}

static void fio_exit fio_s5bd_unregister(void)
{
      unregister_ioengine(&ioengine);
}
