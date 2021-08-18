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

bool mg_send(struct mg_connection *c, const void *buf, size_t len) {
  return true;
}

void mg_mgr_wakeup(struct mg_connection *c) {
  (void) c;
}

struct mg_connection *mg_mkpipe(struct mg_mgr *mgr, mg_event_handler_t fn,
                                void *fn_data) {
  (void) mgr, (void) fn, (void) fn_data;
  return NULL;
}

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


static int mg_lwip_if_listen_tcp_tcpip(struct mg_connection *nc) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->fd;
  struct tcp_pcb *tpcb = TCP_NEW();
  ip_addr_t *ip = (ip_addr_t *) &nc->peer.ip;
  u16_t port = ntohs(nc->peer.port);
  cs->err = TCP_BIND(tpcb, ip, port);
  // DBG(("%p tcp_bind(%s:%u) = %d", nc, IPADDR_NTOA(ip), port, cs->err));
  if (cs->err != ERR_OK) {
    tcp_close(tpcb);
    return -1;
  }
  tcp_arg(tpcb, nc);
  tpcb = tcp_listen(tpcb);
  cs->pcb.tcp = tpcb;
  // tcp_accept(tpcb, mg_lwip_accept_cb);
  return 0;
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

  }
  
  return NULL;
}

#endif
