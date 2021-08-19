#if MG_ARCH == MG_ARCH_LWIP_RAW

int usleep(useconds_t us) {
  (void)us;
  return 0;
}

int clock_gettime(clockid_t clock_id, struct timespec *tp) {
  (void) clock_id; (void)tp;
  return 0;
}

char *realpath(const char *path, char *resolved_path) {
  (void)path; (void)resolved_path; 
  return NULL;
}

struct mg_connection *mg_connect(struct mg_mgr *mgr, const char *url,
                                 mg_event_handler_t fn, void *fn_data) {
  (void) mgr, (void) url, (void) fn, (void) fn_data;
  return NULL;
}

void mg_connect_resolved(struct mg_connection *c) {
  (void) c;
}

void mg_mgr_poll(struct mg_mgr *mgr, int ms) {
  (void) mgr, (void) ms;
}

void mg_mgr_wakeup(struct mg_connection *c) {
  (void) c;
}

struct mg_connection *mg_mkpipe(struct mg_mgr *mgr, mg_event_handler_t fn,
                                void *fn_data) {
  (void) mgr, (void) fn, (void) fn_data;
  return NULL;
}

///////////////
void mg_lwip_mgr_schedule_poll(struct mg_mgr *mgr) {
}

/*
 * Newest versions of LWIP have ip_2_ip4, older have ipX_2_ip,
 * even older have nothing.
 */
#ifndef ip_2_ip4
#ifdef ipX_2_ip
#define ip_2_ip4(addr) ipX_2_ip(addr)
#else
#define ip_2_ip4(addr) (addr)
#endif
#endif

/*
 * Depending on whether Mongoose is compiled with ipv6 support, use right
 * lwip functions
 */
#if MG_ENABLE_IPV6
#define TCP_NEW tcp_new_ip6
#define TCP_BIND tcp_bind_ip6
#define UDP_BIND udp_bind_ip6
#define IPADDR_NTOA(x) ip6addr_ntoa((const ip6_addr_t *)(x))
#define SET_ADDR(dst, src)                               \
  memcpy((dst)->sin6.sin6_addr.s6_addr, (src)->ip6.addr, \
         sizeof((dst)->sin6.sin6_addr.s6_addr))
#else
#define TCP_NEW tcp_new
#define TCP_BIND tcp_bind
#define UDP_BIND udp_bind
#define IPADDR_NTOA ipaddr_ntoa
#define SET_ADDR(dst, src) (dst)->sin.sin_addr.s_addr = ip_2_ip4(src)->addr
#endif

#ifndef MG_SIG_QUEUE_LEN
#define MG_SIG_QUEUE_LEN 32
#endif

struct mg_ev_mgr_lwip_signal {
  int sig;
  struct mg_connection *nc;
};

struct mg_ev_mgr_lwip_data {
  struct mg_ev_mgr_lwip_signal sig_queue[MG_SIG_QUEUE_LEN];
  int sig_queue_len;
  int start_index;
};

static struct mg_ev_mgr_lwip_data lwip_data;

struct mg_lwip_conn_state {
  struct mg_connection *nc;
  struct mg_connection *lc;
  union {
    struct tcp_pcb *tcp;
    struct udp_pcb *udp;
  } pcb;
  err_t err;
  size_t num_sent; /* Number of acknowledged bytes to be reported to the core */
  struct pbuf *rx_chain; /* Chain of incoming data segments. */
  size_t rx_offset; /* Offset within the first pbuf (if partially consumed) */
  /* Last SSL write size, for retries. */
  int last_ssl_write_size;
  /* Whether MG_SIG_RECV is already pending for this connection */
  int recv_pending;
  /* Whether the connection is about to close, just `rx_chain` needs to drain */
  int draining_rx_chain;
};

enum mg_sig_type {
  MG_SIG_CONNECT_RESULT = 1,
  MG_SIG_RECV = 2,
  MG_SIG_CLOSE_CONN = 3,
  MG_SIG_TOMBSTONE = 4,
  MG_SIG_ACCEPT = 5,
};

void mg_lwip_post_signal(enum mg_sig_type sig, struct mg_connection *nc) {
  struct mg_ev_mgr_lwip_data *md = &lwip_data;
  if (md->sig_queue_len >= MG_SIG_QUEUE_LEN) {
    return;
  }
  int end_index = (md->start_index + md->sig_queue_len) % MG_SIG_QUEUE_LEN;
  md->sig_queue[end_index].sig = sig;
  md->sig_queue[end_index].nc = nc;
  md->sig_queue_len++;
  mg_lwip_mgr_schedule_poll(nc->mgr);
}

static struct mg_connection* mg_lwip_if_create_conn() {
  struct mg_connection* nc =
      (struct mg_connection *) calloc(1, sizeof(*nc));
  struct mg_lwip_conn_state *cs =
      (struct mg_lwip_conn_state *) calloc(1, sizeof(*cs));
  if (cs == NULL) return 0;
  cs->nc = nc;
  nc->fd = (void*) cs;
  return nc;
}

static void mg_lwip_tcp_write_tcpip(void *arg) {
  struct mg_lwip_tcp_write_ctx *ctx = (struct mg_lwip_tcp_write_ctx *) arg;
  struct mg_connection *nc = ctx->nc;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  size_t len = MIN(tpcb->mss, MIN(ctx->len, tpcb->snd_buf));
  size_t unsent, unacked;
  if (len == 0) {
    DBG(("%p no buf avail %u %u %p %p", tpcb, tpcb->snd_buf, tpcb->snd_queuelen,
         tpcb->unsent, tpcb->unacked));
    mg_lwip_netif_run_on_tcpip(tcp_output_tcpip, tpcb);
    ctx->ret = 0;
    return;
  }
  unsent = (tpcb->unsent != NULL ? tpcb->unsent->len : 0);
  unacked = (tpcb->unacked != NULL ? tpcb->unacked->len : 0);
  
/*
 * On ESP8266 we only allow one TCP segment in flight at any given time.
 * This may increase latency and reduce efficiency of tcp windowing,
 * but memory is scarce and precious on that platform so we do this to
 * reduce footprint.
 */
#if CS_PLATFORM == CS_P_ESP8266
  if (unacked > 0) {
    ctx->ret = 0;
    return;
  }
  len = MIN(len, (TCP_MSS - unsent));
#endif
  cs->err = tcp_write(tpcb, ctx->data, len, TCP_WRITE_FLAG_COPY);
  unsent = (tpcb->unsent != NULL ? tpcb->unsent->len : 0);
  unacked = (tpcb->unacked != NULL ? tpcb->unacked->len : 0);
  DBG(("%p tcp_write %u = %d, %u %u", tpcb, len, cs->err, unsent, unacked));
  if (cs->err != ERR_OK) {
    /*
     * We ignore ERR_MEM because memory will be freed up when the data is sent
     * and we'll retry.
     */
    ctx->ret = (cs->err == ERR_MEM ? 0 : -1);
    return;
  }
  ctx->ret = len;
  (void) unsent;
  (void) unacked;
}

int mg_lwip_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len) {
  struct mg_lwip_tcp_write_ctx ctx = {.nc = nc, .data = buf, .len = len};
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->sock == INVALID_SOCKET) return -1;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  if (tpcb == NULL) return -1;
  if (tpcb->snd_buf <= 0) return 0;
  // mg_lwip_netif_run_on_tcpip(mg_lwip_tcp_write_tcpip, &ctx);
  return ctx.ret;
}

static void mg_lwip_tcp_error_cb(void *arg, err_t err) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  LOG(LL_DEBUG, ("%p conn error %d", nc, err));
  if (nc == NULL || nc->is_closing) return;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->fd;
  cs->pcb.tcp = NULL; /* Has already been deallocated */
  if (nc->is_connecting) {
    cs->err = err;
    mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
  } else {
    mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
  }
}

static err_t mg_lwip_tcp_sent_cb(void *arg, struct tcp_pcb *tpcb,
                                 u16_t num_sent) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  LOG(LL_DEBUG, ("%p %p %u %p %p", nc, tpcb, num_sent, tpcb->unsent, tpcb->unacked));
  if (nc == NULL) return ERR_OK;
  if (nc->is_draining  && !nc->is_writable &&
      nc->send.len == 0 && tpcb->unsent == NULL && tpcb->unacked == NULL) {
    mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
  }
  if (nc->send.len > 0 || nc->is_writable) {
    mg_lwip_mgr_schedule_poll(nc->mgr);
  }
  (void) num_sent;
  return ERR_OK;
}

static void mg_lwip_recv_common(struct mg_connection *nc, struct pbuf *p) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->fd;
  if (cs->rx_chain == NULL) {
    cs->rx_chain = p;
  } else {
    pbuf_chain(cs->rx_chain, p);
  }
  if (!cs->recv_pending) {
    cs->recv_pending = 1;
    mg_lwip_post_signal(MG_SIG_RECV, nc);
  }
}


static err_t mg_lwip_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb,
                                 struct pbuf *p, err_t err) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  struct mg_lwip_conn_state *cs =
      (nc ? (struct mg_lwip_conn_state *) nc->fd : NULL);
  LOG(LL_DEBUG, ("%p %p %p %p %u %d", nc, cs, tpcb, p, (p != NULL ? p->tot_len : 0),
       err));
  if (p == NULL) {
    if (nc != NULL && !(nc->is_closing)) {
      if (cs->rx_chain != NULL) {
        /*
         * rx_chain still contains non-consumed data, don't close the
         * connection
         */
        cs->draining_rx_chain = 1;
      } else {
        mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
      }
    } else {
      /* Tombstoned connection, do nothing. */
    }
    return ERR_OK;
  } else if (nc == NULL) {
    tcp_abort(tpcb);
    return ERR_ARG;
  }
  /*
   * If we get a chain of more than one segment at once, we need to bump
   * refcount on the subsequent bufs to make them independent.
   */
  if (p->next != NULL) {
    struct pbuf *q = p->next;
    for (; q != NULL; q = q->next) pbuf_ref(q);
  }
  if (cs->rx_chain == NULL) {
    cs->rx_offset = 0;
  } else if (pbuf_clen(cs->rx_chain) >= 4) {
    /* ESP SDK has a limited pool of 5 pbufs. We must not hog them all or RX
     * will be completely blocked. We already have at least 4 in the chain,
     * this one is the last, so we have to make a copy and release this one. */
    struct pbuf *np = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
    if (np != NULL) {
      pbuf_copy(np, p);
      pbuf_free(p);
      p = np;
    }
  }
  mg_lwip_recv_common(nc, p);
  (void) err;
  return ERR_OK;
}

static err_t mg_lwip_accept_cb(void *arg, struct tcp_pcb *newtpcb, err_t err) {
  struct mg_connection *lc = (struct mg_connection *) arg, *nc;
  struct mg_lwip_conn_state *lcs, *cs;
  struct tcp_pcb_listen *lpcb;
  LOG(LL_DEBUG,
      ("%p conn %p from %s:%u", lc, newtpcb,
       IPADDR_NTOA(ipX_2_ip(&newtpcb->remote_ip)), newtpcb->remote_port));
  if (lc == NULL) {
    tcp_abort(newtpcb);
    return ERR_ABRT;
  }
  lcs = (struct mg_lwip_conn_state *) lc->fd;
  lpcb = (struct tcp_pcb_listen *) lcs->pcb.tcp;
#if TCP_LISTEN_BACKLOG
  tcp_accepted(lpcb);
#endif
  nc = mg_if_accept_new_conn(lc);
  if (nc == NULL) {
    tcp_abort(newtpcb);
    return ERR_ABRT;
  }
  cs = (struct mg_lwip_conn_state *) nc->fd;
  cs->lc = lc;
  cs->pcb.tcp = newtpcb;
  /* We need to set up callbacks before returning because data may start
   * arriving immediately. */
  tcp_arg(newtpcb, nc);
  tcp_err(newtpcb, mg_lwip_tcp_error_cb);
  tcp_sent(newtpcb, mg_lwip_tcp_sent_cb);
  tcp_recv(newtpcb, mg_lwip_tcp_recv_cb);
#if LWIP_TCP_KEEPALIVE
  mg_lwip_set_keepalive_params(nc, 60, 10, 6);
#endif
  mg_lwip_post_signal(MG_SIG_ACCEPT, nc);
  (void) err;
  (void) lpcb;
  return ERR_OK;
}

static bool mg_lwip_if_listen_tcp_tcpip(struct mg_connection *nc) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->fd;
  struct tcp_pcb *tpcb = TCP_NEW();
  ip_addr_t *ip = (ip_addr_t *) &nc->peer.ip;
  u16_t port = ntohs(nc->peer.port);
  cs->err = TCP_BIND(tpcb, ip, port);
  LOG(LL_DEBUG, ("%p tcp_bind(%s:%u) = %d", nc, IPADDR_NTOA(ip), port, cs->err));
  if (cs->err != ERR_OK) {
    tcp_close(tpcb);
    return false;
  }
  tcp_arg(tpcb, nc);
  tpcb = tcp_listen(tpcb);
  cs->pcb.tcp = tpcb;
  tcp_accept(tpcb, mg_lwip_accept_cb);
  return true;
}

struct mg_connection *mg_listen(struct mg_mgr *mgr, const char *url,
                                mg_event_handler_t fn, void *fn_data) {
  struct mg_connection *c;
  struct mg_addr addr;

  addr.port = mg_htons(mg_url_port(url));
  if (!mg_aton(mg_url_host(url), &addr)) {
    LOG(LL_ERROR, ("invalid listening URL: %s", url));
    return NULL;
  }
  bool is_udp = strncmp(url, "udp:", 4) == 0;
  c = mg_lwip_if_create_conn();

  if (is_udp) {

  } else {
    if(!mg_lwip_if_listen_tcp_tcpip(c)) {
      // ???? 
    }
  }
  
  return c;
}

bool mg_send(struct mg_connection *c, const void *buf, size_t len) {
  return mg_lwip_if_tcp_send(c, buf, len);
}


#endif
