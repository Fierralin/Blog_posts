---
layout: post
title: "memcached"
date: 2016-12-06 16:25:06
description: memcached
tags: UNIX OS
share: true
intensedebate: true
---

# memcached 处理流程

## main thread建立监听socket


1）主线程首先为自己分配一个main_base；
``` c
main_base = event_init();					//为主线程初始化一个event
```

2）main函数调用server_sockets()函数。该完成主监听socket的建立，而后调用bind()将socket地址（本地IP地址和端口地址）与sfd连接起来，并把该socket描述符添加到libevent事件监控队列中，该socket的事件处理函数是event_handler。
```c
//这边的server_sockets方法主要是socket的创建、bind、listen、accept等操作
//主线程主要用于接收客户端的socket连接，并且将连接交给工作线程接管。  
errno = 0;
if (settings.port
	&& server_sockets(settings.port, tcp_transport, portnumber_file)) {
    vperror("failed to listen on TCP port %d", settings.port);	 
    //主线程创建主监听socket，并把该socket加入到libevent事件队列中
    //当有连接请求到来时调用dispatch_conn_new
    exit(EX_OSERR);
}
```

```c
static int server_socket(const char *interface,  
                         int port,  
                         enum network_transport transport,  
                         FILE *portnumber_file) {  
						..........
if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1)    //bind
					..........
            //创建一个新的事件，指定了state的类型为：conn_listening
            //这个参数主要是指定调用drive_machine这个方法中的conn_listening代码块。  
            if (!(listen_conn_add = conn_new(sfd, conn_listening,  
                                             EV_READ | EV_PERSIST, 1,  
                                             transport, main_base))) {  
                fprintf(stderr, "failed to create listening connection\n");  
                exit(EXIT_FAILURE);  
            }  
            listen_conn_add->next = listen_conn;  
            listen_conn = listen_conn_add;  
}  
```

``` c
conn *conn_new(const int sfd, enum conn_states init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base) {
   //当用户socket的连接有数据传递过来的时候，就会调用event_handler这个回调函数  
    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;
 //将事件添加到libevent的loop循环中
    if (event_add(&c->event, 0) == -1) {
        perror("event_add");
        return NULL;
    }
```

4） event_handler函数调用drive_machine状态处理函数进行处理，初始化状态时conn_listening。

## 创建Worker thread

1）main thread创建n个worker thread。
``` c
    memcached_thread_init(settings.num_threads, main_base); //创建工作线程
```
2）worker thread通过管道方式与其它线程（主要是main thread）进行通信，调用pipe函数，为每一个worker thread创建一个pipe。产生两个fd，一个是管道写入fd，一个是管道读取fd。 worker thread把管道读取fd加到自己的event_base，监听管道读取fd的可读事件。
``` c
	void memcached_thread_init(int nthreads, struct event_base *main_base) {
  		for (i = 0; i < nthreads; i++) {
        	int fds[2];
        	if (pipe(fds)) {
            	perror("Can't create notify pipe");		
        		//创建pipe，用于主线程和工作线程之间的通信
            	exit(1);
        	}
        	//threads是工作线程的基本结构：LIBEVENT_THREAD  
        	//将pipe接收端和写入端都放到工作线程的结构体中  
        	threads[i].notify_receive_fd = fds[0];
        	//接收端，把管道的接收端端描述符notify_receive_fd添加到进libevent事件队列中
        	threads[i].notify_send_fd = fds[1];
       		//写入端 ，把管道的写入端描述符notify_send_fd 添加到进libevent事件队列中
		}
	}
```

3）同时每个worker thread也分配了独立的event_base，为线程设置读写事件监听，注册事件处理函数thread_libevent_process，绑定CQ链表等初始化信息。

``` c
	static void setup_thread(LIBEVENT_THREAD *me) {	//线程信息初始化
    //创建一个event_base  
    //一般情况下每个独立的线程都应该有自己独立的event_base  
    me->base = event_init();
    if (! me->base) {
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }
    //初始化一个event（事件）结构体，设置事件的文件描述符、事件类型（读IO事件或者写IO事件等）
    //这里主要创建pipe的读事件EV_READ的监听  
    //当pipe中有写入事件的时候，libevent就会回调thread_libevent_process方法
    // 注册事件处理函数thread_libevent_process
    //EV_PERSIST表示事件的回调函数执行完后，不会把事件listenEvent从base中移除
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);      
    event_base_set(me->base, &me->notify_event);//相应的事件设置相应的event_base
    if (event_add(&me->notify_event, 0) == -1) {					
    //把事件添加到队列（就绪队列、active队列等），队列由event对应的event_base管理
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }
    //初始化一个工作队列，为每个线程创建连接队列CQ
    me->new_conn_queue = malloc(sizeof(struct conn_queue));			
    if (me->new_conn_queue == NULL) {
        perror("Failed to allocate memory for connection queue");
        exit(EXIT_FAILURE);
    }
    cq_init(me->new_conn_queue);
```


4）当main thread往某个线程的管道写入fd写数据时，触发事件。

## 连接处理

1） main thread监听连接时，一旦client socket连接有数据传递过来，就会调用event_handler这个回调函数，event_handler将事件处理转交给drive_machine。
``` c
void event_handler(const int fd, const short which, void *arg) {  
    conn *c;  
    //组装conn结构  
    c = (conn *)arg;  
    assert(c != NULL);  
    c->which = which;  
    if (fd != c->sfd) {  
        if (settings.verbose > 0)  
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");  
        conn_close(c);  
        return;  
    }  
    //最终转交给了drive_machine这个方法  
    //memcache的大部分的网络事件都是由drive_machine这个方法来处理的  
    //drive_machine这个方法主要通过c->state这个事件的类型来处理不同类型的事件     
    drive_machine(c);  
    /* wait for next event */  
    return;  
}  
```
2）此时处于conn_listening 状态，当有连接请求到来时，调用accept(sfd,,)接受请求， 并调用dispatch_conn_new()函数分发请求。
``` c
 case conn_listening:					 
       //我们可以看到下面的代码是accept，接受客户端的socket连接的代码  
            addrlen = sizeof(addr);
#ifdef HAVE_ACCEPT4
            if (use_accept4) {
                sfd = accept4(c->sfd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
            } else {
                sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
            }
#else
            sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);      //accept
#endif
            if (sfd == -1) {    //此时的sfd是接收到的客户端socket的fd
                if (use_accept4 && errno == ENOSYS) {
                    use_accept4 = 0;
                    continue;
                }
                perror(use_accept4 ? "accept4()" : "accept()");
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* these are transient, so don't log anything */
                    stop = true;
                } else if (errno == EMFILE) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Too many open connections\n");
                    accept_new_conns(false);
                    stop = true;
                } else {
                    perror("accept()");
                    stop = true;
                }
                break;
            }
            if (!use_accept4) {
                if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
                    perror("setting O_NONBLOCK");
                    close(sfd);
                    break;
                }
            }
            if (settings.maxconns_fast &&
                stats.curr_conns + stats.reserved_fds >= settings.maxconns - 1) {
                res = write(sfd, str, strlen(str));             //write
                close(sfd);
                STATS_LOCK();
                stats.rejected_conns++;
                STATS_UNLOCK();
            } else {
        //如果客户端用socket连接上来，则会调用这个分发逻辑的函数  
        //这个函数会将连接信息分发到某一个工作线程中，然后工作线程接管具体的读写操作
                dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
                                     DATA_BUFFER_SIZE, tcp_transport);
            }
            stop = true;
            break;

```

3） dispatch_conn_new函数中会将当前用户的连接信息放入一个CQ_ITEM，用于存储连接的基本信息，通过求余数的方法来得到当前的连接需要哪个worker thread来接管，并且将CQ_ITEM放入这个work thread的CQ处理队列。然后main thread会向pipe中写入一个字节的数据’c’来通知worker thread。

``` c
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport) {
//每个连接连上来的时候，都会申请一块CQ_ITEM的内存块，用于存储连接的基本信息  
    CQ_ITEM *item = cqi_new();
    char buf[1];
    //如果item创建失败，则关闭连接
    if (item == NULL) {
        close(sfd);
        /* given that malloc failed this may also fail, but let's try */
        fprintf(stderr, "Failed to allocate memory for connection object\n");
        return ;
    }
//这个方法非常重要。主要是通过求余数的方法来得到当前的连接需要哪个线程来接管  
//而且last_thread会记录每次最后一次使用的工作线程
//每次记录之后就可以让工作线程进入一个轮询，保证了每个工作线程处理的连接数的平衡  
    int tid = (last_thread + 1) % settings.num_threads;
//获取线程的基本结构
    LIBEVENT_THREAD *thread = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;
 //向工作线程的队列中放入CQ_ITEM  
    cq_push(thread->new_conn_queue, item);

    MEMCACHED_CONN_DISPATCH(sfd, thread->thread_id);
    buf[0] = 'c';
//向工作线程的pipe中写入1个字节的数据  
    if (write(thread->notify_send_fd, buf, 1) != 1) {
        perror("Writing to thread notify pipe");
    }
}

```
## Worker thread命令处理(以set命令为例）

1）worker thread事件处理函数thread_libevent_process读取pipe中一个字节的数据，如果为’c’，则从该worker thread的CQ队列中取出一个CQ_ITEM进行处理，并调用conn_new()函数新建连接。
``` c
static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    char buf[1];
    //确保正确读取pipe中一个字节的数据
    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");

    switch (buf[0]) {
    case 'c':
    //从工作线程的队列中获取一个CQ_ITEM连接信息
    item = cq_pop(me->new_conn_queue);
   //conn_new这个方法非常重要，主要是创建socket的读写等监听事件。  
   //init_state 为初始化的类型，主要在drive_machine中通过这个状态类判断处理类型  
    if (NULL != item) {
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base);
        if (c == NULL) {
            if (IS_UDP(item->transport)) {
                fprintf(stderr, "Can't listen for events on UDP socket\n");
                exit(1);
            } else {
                if (settings.verbose > 0) {
                    fprintf(stderr, "Can't listen for events on fd %d\n",
                        item->sfd);
                }
                close(item->sfd);
            }
        } else {
            c->thread = me;
        }
        cqi_free(item);
    }
        break;
    /* we were told to pause and report in */
    case 'p':
    register_thread_initialized();
        break;
    }
}
```
2）conn_new函数中调用libevent方法， 内部把event处理函数绑定sfd(client fd,感觉在这里用的都是sfd)，此时item中的状态是conn_new_cmd。

3） 处于conn_new_cmd状态时，第一次有请求过来，调用reset_cmd_handler，重新回到状态机执行下一次循环，进入conn_waiting分支。
``` c
 case conn_new_cmd:
            --nreqs;
            if (nreqs >= 0) {
                reset_cmd_handler(c);  //第一次请求
            } else {
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.conn_yields++;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                if (c->rbytes > 0) {
                    /* We have already read in data into the input buffer,
                       so libevent will most likely not signal read events
                       on the socket (unless more data is available. As a
                       hack we should just put in a request to write data,
                       because that should be possible ;-)
                    */
                    if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                        if (settings.verbose > 0)
                            fprintf(stderr, "Couldn't update event\n");
                        conn_set_state(c, conn_closing);
                        break;
                    }
                }
                stop = true;
            }
            break;
```

``` c
static void reset_cmd_handler(conn *c) {
    c->cmd = -1;
    c->substate = bin_no_state;
    if(c->item != NULL) {
        item_remove(c->item);
        c->item = NULL;
    }
    conn_shrink(c);//这个方法是检查c->rbuf容器的大小
    if (c->rbytes > 0) {
        conn_set_state(c, conn_parse_cmd);
    } else {
        conn_set_state(c, conn_waiting);
     //第一次请求时c->rbytes为初值0，状态机进入conn_waiting分支。
    }
}
```
4） conn_waiting直接将状态改为conn_read分支，并且结束状态机。
状态处于conn_read状态，并且第二次有请求通知过来时，conn_read调用 try_read_network函数读出请求。
``` c
  case conn_waiting:
            if (!update_event(c, EV_READ | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                break;
            }

            conn_set_state(c, conn_read);        //直接将状态改为conn_read
            stop = true;                                  //状态机停止
            break;
```

``` c
case conn_read:
//调用try_read_network读出请求
            res = IS_UDP(c->transport) ? try_read_udp(c) : try_read_network(c);
            switch (res) {
            case READ_NO_DATA_RECEIVED:
                conn_set_state(c, conn_waiting);
                break;
            case READ_DATA_RECEIVED:
                conn_set_state(c, conn_parse_cmd);
                break;
            case READ_ERROR:
                conn_set_state(c, conn_closing);
                break;
            case READ_MEMORY_ERROR: /* Failed to allocate more memory */
                /* State already set by try_read_network */
                break;
            }
            break;
```

5） try_read_network调用read()函数来读取请求，如果读取失败，则返回conn_closing，去关闭客户端的连接；如果没有读取到任何数据，则会返回conn_waiting，继续等待客户端的事件到来，并且退出drive_machine的循环；如果数据读取成功，则会将状态转交给conn_parse_cmd处理，读取到的数据会存储在c->rbuf容器中。
``` c
static enum try_read_result try_read_network(conn *c) {
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;  //conn_waiting
    int res;
    int num_allocs = 0;
    assert(c != NULL);

    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) {
            if (num_allocs == 4) {
                return gotdata;
            }
            ++num_allocs;
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf) {
                STATS_LOCK();
                stats.malloc_fails++;
                STATS_UNLOCK();
                if (settings.verbose > 0) {
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                }
                c->rbytes = 0; /* ignore what we read */
                out_of_memory(c, "SERVER_ERROR out of memory reading request");
                c->write_and_go = conn_closing;
                return READ_MEMORY_ERROR;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes; //读buffer的空间还剩余多少大小可以用
        res = read(c->sfd, c->rbuf + c->rbytes, avail);      //read,往剩下的可用的地方里读
        if (res > 0) {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.bytes_read += res;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            gotdata = READ_DATA_RECEIVED;                    //conn_parse_cmd
            c->rbytes += res;
//rbytes是当前指针rcurr至读buffer末尾的数据大小，这里可简单地理解为对rbytes的初始化。
            if (res == avail) {   //可能还没读完，此时读buffer可用空间满了
                continue;
            } else {
                break;
            }
        }
        if (res == 0) {
            return READ_ERROR;                                 //conn_closing
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return READ_ERROR；       //出错，conn_closing
        }
    }
    return gotdata;
}
```


6） conn_parse_cmd主要的工作就是用来解析命令。主要通过try_read_command这个方法来读取c->rbuf中的命令数据，通过\n来分隔数据报文的命令。如果c->rbuf内存块中的数据匹配不到\n，则返回继续等待客户端的命令数据报文到来conn_waiting；否则就会转交给process_command方法，来处理具体的命令（命令解析会通过\0符号来分隔）。

``` c
//调用此函数来处理c->rbuf中的命令解析  
static int try_read_command(conn *c) {  
    assert(c != NULL);  
    assert(c->rcurr <= (c->rbuf + c->rsize));
    assert(c->rbytes > 0);  
    if (c->protocol == negotiating_prot || c->transport == udp_transport) {  
        if ((unsigned char) c->rbuf[0] == (unsigned char) PROTOCOL_BINARY_REQ) {  
            c->protocol = binary_prot;  
        } else {  
            c->protocol = ascii_prot;  
        }  

        if (settings.verbose > 1) {  
            fprintf(stderr, "%d: Client using the %s protocol\n", c->sfd,  
                    prot_text(c->protocol));  
        }  
    }  
    //有两种模式，是否是二进制模式还是ascii模式  
    if (c->protocol == binary_prot) {  
        //更多代码  
    } else {  
        //处理非二进制模式的命令解析  
        char *el, *cont;  

        //如果c->rbytes==0 表示buf容器中没有可以处理的命令报文，则返回0  
        //0 是让程序继续等待接收新的客户端报文  
        if (c->rbytes == 0)  
            return 0;  

        //查找命令中是否有\n，memcache的命令通过\n来分割  
        //当客户端的数据报文过来的时候，Memcached通过查找接收到的数据中是否有\n换行符来判断收到的命令数据包是否完整  
        el = memchr(c->rcurr, '\n', c->rbytes);  

        //如果没有找到\n，说明命令不完整，则返回0，继续等待接收新的客户端数据报文  
        if (!el) {  
         //c->rbytes是接收到的数据包的长度  
        //如果一次接收的数据报文大于了1K，则Memcached回去判断这个请求是否太大了，是否有问题？  
            //然后会关闭这个客户端的链接  
            if (c->rbytes > 1024) {  
                /*
                 * We didn't have a '\n' in the first k. This _has_ to be a
                 * large multiget, if not we should just nuke the connection.
                 */  
                char *ptr = c->rcurr;  
                while (*ptr == ' ') { /* ignore leading whitespaces */  
                    ++ptr;  
                }  

                if (ptr - c->rcurr > 100  
                        || (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {  

                    conn_set_state(c, conn_closing);  
                    return 1;  
                }  
            }  

            return 0;  
        }  
        //如果找到了\n，说明c->rcurr中有完整的命令了  
        cont = el + 1; //下一个命令开始的指针节点  
        //判断是否是\r\n,如果是\r\n，则el往前移一位  
        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {  
            el--;  
        }  
        //然后将命令的最后一个字符用 \0（字符串结束符号）来分隔  
        *el = '\0';  

        assert(cont <= (c->rcurr + c->rbytes));  

        c->last_cmd_time = current_time; //最后命令时间  
        //转交process_command处理命令，c->rcurr就是命令  
        process_command(c, c->rcurr);  

        c->rbytes -= (cont - c->rcurr);
        c->rcurr = cont;             //将c->rcurr指向到下一个命令的指针节点  

        assert(c->rcurr <= (c->rbuf + c->rsize));  
    }  

    return 1;  
}  

```
7） process_command调用tokenize_command对cmd进行解析，将命令拆解成多个元素（KEY的最大长度250）。我们以set命令为例，最终会跳转到process_set_command这个命令。 process_*_command这一系列就是处理具体的命令逻辑的。

```  c
 //这里就是对命令的解析和执行了
//然后根据命令类型再次改变conn_state使程序再次进入状态机
//command此时的指针值等于conn的rcurr

static void process_command(conn *c, char *command) {
    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm; //命令类型
    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        out_of_memory(c, "SERVER_ERROR out of memory preparing response");
        return;
    }
    /**
    下面这个tokenize_command是一个词法分析，把command分解成一个个token
    */
    ntokens = tokenize_command(command, tokens, MAX_TOKENS);
    //下面是对上面分解出来的token再进行语法分析，解析命令，下面的comm变量为最终解析出来命令类型
    if (ntokens >= 3 &&
        ((strcmp(tokens[COMMAND_TOKEN].value, "get") == 0) ||
         (strcmp(tokens[COMMAND_TOKEN].value, "bget") == 0))) {
        process_get_command(c, tokens, ntokens, false);
    } else if ((ntokens == 6 || ntokens == 7) &&
               ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = NREAD_PREPEND)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = NREAD_APPEND)) )) {
        //add/set/replace/prepend/append为“更新”命令，调用同一个函数执行命令。详见process_update_command定义处
        process_update_command(c, tokens, ntokens, comm, false);
    }
}  
```
8） 由process_update_command执行后进入conn_nread状态，process_update_command为要set的数据（称为item）分配了内存，其实只执行了set命令的一半，剩下的一半由conn_nread完成。

``` c
static void process_update_command(conn *c, token_t *tokens, const size_t ntokens, int comm, bool handle_cas) {
    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        //key过长，out_string函数的作用是输出响应，
        return;
    }
    key = tokens[KEY_TOKEN].value;     //键名
    nkey = tokens[KEY_TOKEN].length; //键长度
    //下面这个if同时把命令相应的参数（如缓存超时时间等）赋值给相应变量：exptime_int等
    if (! (safe_strtoul(tokens[2].value, (uint32_t *)&flags)
           && safe_strtol(tokens[3].value, &exptime_int)
           && safe_strtol(tokens[4].value, (int32_t *)&vlen))) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }
    exptime = exptime_int;
    if (exptime < 0)
        exptime = REALTIME_MAXDELTA + 1;
    //在这里执行内存分配工作。
    it = item_alloc(key, nkey, flags, realtime(exptime), vlen);
    ITEM_set_cas(it, req_cas_id);
    c->item = it;                    //将item指针指向分配的item空间
    c->ritem = ITEM_data(it); //将 ritem 指向 it->data中要存放 value 的空间地址
    c->rlbytes = it->nbytes;   //data的大小
    c->cmd = comm;            //命令类型
    conn_set_state(c, conn_nread); //继续调用状态机，执行命令的另一半工作。
```
9）由conn_nread读出命令行后所剩的数据部分，调用read()函数，将所读出的数据部分放入process_update_command分配的新内存中，调用complete_nread进行收尾工作。

``` c
case conn_nread:
   /* 由process_update_command执行后进入此状态，process_update_command函数只     执行了add/set/replace 等命令的一半,剩下的一半由这里完成。
      例如如果是上面的set命令，process_update_command只完成了“命令行”部分，分配了item空间，但还没有把value塞到对应的 item中去。因此，在这一半要完成的动作就是把value的数据从socket中读出来，塞到刚拿到的item空间中去  */

 //要读的“value数据”还剩下多少字节
//如果是第一次由process_update_command进入到此，rlbytes此时在process_update_command中被初始化为item->nbytes， 即value的总字节数
            if (c->rlbytes == 0) {
  /** rlbytes为0才读完，否则状态机一直会进来这个conn_nread分支继续读value数据，
        读完就调用complete_nread完成收尾工作，程序会跟着complete_nread进入下一个
        状态。所以执行完complete_nread会break; */
                complete_nread(c);
                break;
            }
 //如果还有数据没读完，继续往下执行。可知，下面的动作就是继续从buffer中读value    数据往item中的data的value位置塞。
            if (c->rbytes > 0) {

                int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                if (c->ritem != c->rcurr) {
                    memmove(c->ritem, c->rcurr, tocopy);
          //往分配的item中塞，即为key设置value的过程
                }
                c->ritem += tocopy;
                c->rlbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                if (c->rlbytes == 0) {
                    break;
                }
            }
            //这里往往是我们先前读到buffer的数据还没足够的情况下，从socket中读。
            res = read(c->sfd, c->ritem, c->rlbytes);/
            if (res > 0) {
                if (c->rcurr == c->ritem) {
                    c->rcurr += res;
                }
                c->ritem += res;
                c->rlbytes -= res;
                break;
            }
}
```
10）complete_nread根据连接的协议类型调用complete_nread_ascii或  complete_nread_binary函数，这两个函数继续调用out_string函数向客户端输出命令执行的结果。

``` c
static void complete_nread_ascii(conn *c) {
     ret = store_item(it, comm, c);
     switch (ret)
     {
      case STORED:
          out_string(c, "STORED");
          break;
      }
}
```
11）out_string函数转回conn_write,在该状态下调用add_iov函数；再继续到conn_mwrite状态,后续步骤将会在下面提到。

## 消息回应

``` c
msghdr结构：
struct msghdr {  
     void *msg_name;  
     socklen_t msg_namelen;  
     struct iovec *msg_iov;  
     size_t msg_iovlen;  
     void *msg_control;  
     size_t msg_controllen;  
     int msg_flags;  
};  
```

iovc结构：
```c
struct iovec {  
    void *iov_base;  /* Pointer to data. */  
    size_t iov_len;    /* Length of data. */  
};  
```

```c
conn结构中iovc和msghdr初始化 ：
typedef struct conn conn;  
struct conn {  
    //....  
    /* data for the mwrite state */  
    //iov主要存储iov的数据结构  
    //iov数据结构会在conn_new中初始化，初始化的时候，系统会分配400个iovec的结构，最高水位600个  
    struct iovec *iov;    
    int    iovsize;   /* number of elements allocated in iov[] */  
    int    iovused;   /* number of elements used in iov[] */  
  //msglist主要存储msghdr的列表数据结构  
  //msglist数据结构在conn_new中初始化的时候，系统会分配10个结构，初始化为10个，最高水位100，不够用的时候会realloc，每次扩容都会扩容一倍   
    struct msghdr *msglist;  
    int    msgsize;   /* number of elements allocated in msglist[] */  
    //msglist已经使用的长度  
    int    msgused;   /* number of elements used in msglist[] */  
    //这个参数主要帮助记录那些msglist已经发送过了，哪些没有发送过。  
    int    msgcurr;   /* element in msglist[] being transmitted now */  
   //当前消息的字节数
    int    msgbytes;  /* number of bytes in current msg */  
}  
```

在conn_new函数中对iovc和msghdr进行初始化
``` c
conn *conn_new(const int sfd, enum conn_states init_state,  
        const int event_flags, const int read_buffer_size,  
        enum network_transport transport, struct event_base *base) {  
//...  
        c->rbuf = c->wbuf = 0;  
        c->ilist = 0;  
        c->suffixlist = 0;  
        c->iov = 0;  
        c->msglist = 0;  
        c->hdrbuf = 0;  

        c->rsize = read_buffer_size;  
        c->wsize = DATA_BUFFER_SIZE;  
        c->isize = ITEM_LIST_INITIAL;  
        c->suffixsize = SUFFIX_LIST_INITIAL;  
        c->iovsize = IOV_LIST_INITIAL; //初始化400  
        c->msgsize = MSG_LIST_INITIAL; //初始化10  
        c->hdrsize = 0;  

        c->rbuf = (char *) malloc((size_t) c->rsize);  
        c->wbuf = (char *) malloc((size_t) c->wsize);  
        c->ilist = (item **) malloc(sizeof(item *) * c->isize);  
        c->suffixlist = (char **) malloc(sizeof(char *) * c->suffixsize);  
        c->iov = (struct iovec *) malloc(sizeof(struct iovec) * c->iovsize); //初始化iov  
        c->msglist = (struct msghdr *) malloc(  
                sizeof(struct msghdr) * c->msgsize); //初始化msglist  
//...  
}  
```

1）如果请求的命令为get,最终会跳转到process_get_command这个命令处理函数。
process_get_command取出key，判断出key符合规格后，调用item_get从memcached 的内存中取出数据，判断conn-> ilist（ c->ilist 存放用于向外部写数据的rbuf  ）是否足够大，不够则重新分配内存。


```c
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {  
    char *key;  
    size_t nkey;  
    int i = 0;  
    item *it;  
    token_t *key_token = &tokens[KEY_TOKEN];  
    char *suffix;  
    assert(c != NULL);  

    do {  
        //因为一个get命令可以同时获取多条记录的内容  
        //比如get key1 key2 key3  
        while(key_token->length != 0) {  

            key = key_token->value;  
            nkey = key_token->length;  

            it = item_get(key, nkey);  

            if (it) {  

                /*
                 * Construct the response. Each hit adds three elements to the
                 * outgoing data list:
                 *   "VALUE "
                 *   key
                 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
                 */  

                if (return_cas)  
                {  
                    ...//不是cas  
                }  
                else  
                {  
                  //填充要返回的信息  
                  if (add_iov(c, "VALUE ", 6) != 0 ||//如果add_iov成功，则返回0  
                      add_iov(c, ITEM_key(it), it->nkey) != 0 ||  
                      add_iov(c, ITEM_suffix(it), it->nsuffix + it->nbytes) != 0)  
                      {  
                          item_remove(it);//引用计数减一  
                          break;  
                      }  
                }  

                //刷新这个item的访问时间以及在LRU队列中的位置  
                item_update(it);  

                //并不会马上放弃对这个item的占用。因为在add_iov函数中，memcached并
                //不会复制一份item，而是直接使用item结构体本身的数据。故不能马上解除对  
                //item的引用，不然其他worker线程就有机会把这个item释放,导致野指针  
                *(c->ilist + i) = it;   //把这个item放到ilist数组中，日后会进行释放的  
                i++;  

            }   

            key_token++;  
        }  


        //因为调用一次tokenize_command最多只可以解析MAX_TOKENS-1个token，但  
        //get命令的键值key个数可以有很多个，所以此时就会出现后面的键值  
        //不在第一次tokenize的tokens数组中，此时需要多次调用tokenize_command  
        //函数，把所有的键值都tokenize出来。注意，此时还是在get命令中。  
        //当然在看这里的代码时直接忽略这种情况，我们只考虑"get tk"命令  
        if(key_token->value != NULL) {  
            ntokens = tokenize_command(key_token->value, tokens, MAX_TOKENS);  
            key_token = tokens;  
        }  

    } while(key_token->value != NULL);  
    c->icurr = c->ilist;  
    c->ileft = i;  

    /*
        If the loop was terminated because of out-of-memory, it is not
        reliable to add END\r\n to the buffer, because it might not end
        in \r\n. So we send SERVER_ERROR instead.
    */  
    if (key_token->value != NULL || add_iov(c, "END\r\n", 5) != 0  
        || (IS_UDP(c->transport) && build_udp_headers(c) != 0)) {  
        out_of_memory(c, "SERVER_ERROR out of memory writing get response");  
    }  
    else {  
        conn_set_state(c, conn_mwrite);//更改conn的状态  
        c->msgcurr = 0;  
    }  
}  

```

 2）process_get_command调用add_iov将需要发送的数据，分成N多个IOV的块，并添加到msghdr的结构中去。在这个过程中，如果msghdr不够用调用add_msghdr函数确保msghdr 足够； 调用ensure_iov_space函数确保iov足够。
循环执行，直到命令行中的命令全部被处理，添加结束标志，将状态将状态修改为conn_mwrite向客户端写数据。

``` c
static int add_iov(conn *c, const void *buf, int len) {  
    struct msghdr *m;  
    int leftover;  
    bool limit_to_mtu;  

    assert(c != NULL);  

    //在process_command函数中，一开始会调用add_msghdr函数，而add_msghdr会把  
    //msgused++，所以msgused会等于1,即使在conn_new函数中它被赋值为0  
    do {  
        m = &c->msglist[c->msgused - 1];  

        /*
         * Limit UDP packets, and the first payloads of TCP replies, to
         * UDP_MAX_PAYLOAD_SIZE bytes.
         */  
        limit_to_mtu = IS_UDP(c->transport) || (1 == c->msgused);  

        /* We may need to start a new msghdr if this one is full. */  
        if (m->msg_iovlen == IOV_MAX ||//一个msghdr最多只能有IOV_MAX个iovec结构体  
            (limit_to_mtu && c->msgbytes >= UDP_MAX_PAYLOAD_SIZE)) {  
            add_msghdr(c);  
            m = &c->msglist[c->msgused - 1];  
        }  

        //保证iovec数组是足够用的。调用add_iov函数一次会消耗一个iovec结构体  
        //所以可以在插入数据之前保证iovec数组是足够用的  
        if (ensure_iov_space(c) != 0)  
            return -1;  

        /* If the fragment is too big to fit in the datagram, split it up */  
        if (limit_to_mtu && len + c->msgbytes > UDP_MAX_PAYLOAD_SIZE) {  
            leftover = len + c->msgbytes - UDP_MAX_PAYLOAD_SIZE;  
            len -= leftover;  
        } else {  
            leftover = 0;  
        }  

        m = &c->msglist[c->msgused - 1];  

        //用一个iovec结构体指向要回应的数据  
        m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;  
        m->msg_iov[m->msg_iovlen].iov_len = len;  

        c->msgbytes += len;  
        c->iovused++;  
        m->msg_iovlen++;  

        buf = ((char *)buf) + len;  
        len = leftover;  
    } while (leftover > 0); //循环处理知道命令行中的命令全部被处理

    return 0;  
}  

```

3）conn_mwrite 调用`transmit`函数，该函数每次从从c->msglist取出一个待发送的msghdr结构，调用sendmsg对客户端进行发送。当数据发送成功后，会跳转到conn_new_cmd这个状态继续处理，然后进入reset_cmd_handler方法，如果还有剩余未解析的命令的话，继续跳转到conn_parse_cmd解析命令，否则回到conn_waiting状态，继续等待等待新的数据到来。

``` c
static enum transmit_result transmit(conn *c) {    //这个方法主要向客户端写数据  
//如果数据没有发送完，则会一直循环conn_mwrite这个状态，直到数据发送完成为止  
    assert(c != NULL);
//每次发送之前，都会来校验前一次的数据是否发送完了  
//如果前一次的msghdr结构体内的数据已经发送完了，则c->msgcurr指针就会往后移动一位，到下一个等待发送的msghdr结构体指针上
    if (c->msgcurr < c->msgused &&
            c->msglist[c->msgcurr].msg_iovlen == 0) {
        /* Finished writing the current msg; advance to the next. */
        c->msgcurr++;
    }
 //如果c->msgcurr（已发送）小于c->msgused（已使用），则就可以知道还没发送完，则需要继续发送  
//如果c->msgcurr（已发送）等于c->msgused（已使用），则说明已经发送完了，返回TRANSMIT_COMPLETE状态
    if (c->msgcurr < c->msgused) {
        ssize_t res;
//从c->msglist取出一个待发送的msghdr结构  
        struct msghdr *m = &c->msglist[c->msgcurr];
//向客户端发送数据
        res = sendmsg(c->sfd, m, 0);				//send
        if (res > 0) {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.bytes_written += res;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            /* We've written some of the data. Remove the completed
               iovec entries from the list of pending writes. */
            while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) {
                res -= m->msg_iov->iov_len;
                m->msg_iovlen--;
                m->msg_iov++;
            }
            /* Might have written just part of the last iovec entry;
               adjust it so the next write will do the rest. */
            if (res > 0) {
                m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
                m->msg_iov->iov_len -= res;
            }
            return TRANSMIT_INCOMPLETE;
        }
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                return TRANSMIT_HARD_ERROR;
            }
            return TRANSMIT_SOFT_ERROR;
        }
        /* if res == 0 or res == -1 and error is not EAGAIN or EWOULDBLOCK,
           we have a real error, on which we close the connection */
        if (settings.verbose > 0)
            perror("Failed to write, and not due to blocking");

        if (IS_UDP(c->transport))
            conn_set_state(c, conn_read);
        else
            conn_set_state(c, conn_closing);
        return TRANSMIT_HARD_ERROR;
    } else {
        return TRANSMIT_COMPLETE;
    }
}

```

``` c
case conn_mwrite: //这个conn_mwrite是向客户端写数据  
          if (IS_UDP(c->transport) && c->msgcurr == 0 && build_udp_headers(c) != 0) {
            if (settings.verbose > 0)
              fprintf(stderr, "Failed to build UDP headers\n");
            conn_set_state(c, conn_closing);
            break;
          }
            //返回transmit_result枚举类型，用于判断是否写成功，如果失败，则关闭连接  
            switch (transmit(c)) {
            case TRANSMIT_COMPLETE: //如果向客户端发送数据成功  
                if (c->state == conn_mwrite) {
                    conn_release_items(c);
                    if(c->protocol == binary_prot) {
                        conn_set_state(c, c->write_and_go);
                    } else {
                        conn_set_state(c, conn_new_cmd);//这边是TCP的状态  
                        //状态又会切回到conn_new_cmd这个状态  
                        //conn_new_cmd主要是继续解析c->rbuf容器中剩余的命令参数
                    }
                } else if (c->state == conn_write) {
                    if (c->write_and_free) {
                        free(c->write_and_free);
                        c->write_and_free = 0;
                    }
                    conn_set_state(c, c->write_and_go);
                } else {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Unexpected state %d\n", c->state);
                    conn_set_state(c, conn_closing);
                }
                break;
            case TRANSMIT_INCOMPLETE:
            case TRANSMIT_HARD_ERROR:
                break;                   /* Continue in state machine. */
            case TRANSMIT_SOFT_ERROR:
                stop = true;
                break;
            }
            break;
```
