#define MG_ENABLE_SOCKET 0
#define MG_ENABLE_LINES 1
#define MG_ENABLE_MIP 1
#define MG_ENABLE_PACKED_FS 0

#include <assert.h>
#include "mongoose.c"

#include "driver_mock.c"

static bool test_init(uint8_t *mac, void *data) {
  (void) mac, (void) data;
  printf("test_init\n");
  return true;
}

static size_t test_tx(const void *buf, size_t len, void *data) {
  (void) buf, (void) len, (void) data;
  printf("test_tx\n");
  return len;
}

static size_t test_rx(void *buf, size_t len, void *data) {
  (void) buf, (void) len, (void) data;
  printf("test_rx\n");
  return len;
}

static bool test_up(void *data) {
  (void) data;
  printf("test_up\n");
  return true;
}

static void test_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  (void)c, (void)ev, (void)ev_data, (void)fn_data;
  printf("test_cb\n");
}

struct mip_driver mip_driver_test = {test_init, test_tx, test_rx, test_up, 0};

static void test_inputs(void) {
  struct mip_if mip_if = {0};
  mip_if.driver = &mip_driver_test;

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);

  mip_init(&mgr, &mip_if);

  struct mg_connection *c = mg_http_listen(&mgr, "127.0.0.1:80", test_cb, NULL);
  assert(c != NULL);
  for(int i = 0; i < 1000; i++) {
    mg_mgr_poll(&mgr, 1);
  }

  mg_mgr_free(&mgr);
  free((char*)mip_if.rx.ptr);
  free((char*)mip_if.tx.ptr);
}

static void test_queue(void) {
  static uint8_t
      buf[sizeof(size_t) + sizeof(uint16_t) + 3];  // fit 1 element but not 2
  uint16_t val = 1234;
  static struct queue q = {buf, sizeof(buf), 0, 0};

  // Write to an empty queue, and read back
  assert(q_avail(&q) == 0);
  assert(q_write(&q, &val, sizeof(val)) == true);
  assert(q_avail(&q) == sizeof(val));
  assert(q.head > q.tail);
  // Only one element may fit
  assert(q_write(&q, &val, sizeof(val)) == false);
  val = 0;
  assert(q_read(&q, &val) == sizeof(val));
  assert(val == 1234);
  assert(q_avail(&q) == 0);

  // Second write - wrap over the buffer boundary
  assert(q_write(&q, &val, sizeof(val)) == true);
  assert(q_avail(&q) == sizeof(val));
  assert(q.head < q.tail);
  // Only one element may fit
  assert(q_write(&q, &val, sizeof(val)) == false);
  val = 0;
  assert(q_read(&q, &val) == sizeof(val));
  assert(val == 1234);
  assert(q_avail(&q) == 0);
}

static void test_statechange(void) {
  char tx[1540];
  struct mip_if iface;
  memset(&iface, 0, sizeof(iface));
  iface.ip = mg_htonl(0x01020304);
  iface.state = MIP_STATE_READY;
  iface.tx.ptr = tx, iface.tx.len = sizeof(tx);
  iface.driver = &mip_driver_mock;
  onstatechange(&iface);
}

int main(void) {
  test_queue();
  test_statechange();
  test_inputs();
  printf("SUCCESS\n");
  return 0;
}
