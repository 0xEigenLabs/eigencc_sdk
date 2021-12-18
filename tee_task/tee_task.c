#include <netdb.h>

#include "include/tee_task.h"
#include "include/eigentee.h"

eigen_enclave_info_t *g_enclave_info = NULL;
eigen_auditor_set_t *g_auditors = NULL;
int32_t g_tms_port = 8082;

int submit_task(const char *method, const char *args, const char *uid,
                const char *token, char **output, size_t *output_size) {
  struct sockaddr_in tms_addr;
  char recvbuf[2048] = {0};
  int ret;
  struct hostent *hptr;
  const char *fns_hostname = "fns";

  if ((hptr = gethostbyname(fns_hostname)) == NULL) {
    printf("[TEESDK] gethostbyname error for host: %s\n", fns_hostname);
    return EXIT_FAILURE;
  }

  printf("[TEESDK] official hostname:%s\n", hptr->h_name);

  if (!hptr->h_addr_list[0]) {
    printf("[TEESDK] empty address\n");
    return EXIT_FAILURE;
  }

  tms_addr.sin_family = AF_INET;
  // tms_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  tms_addr.sin_addr.s_addr = *(u_long *)hptr->h_addr_list[0];
  tms_addr.sin_port = htons(g_tms_port);

  printf("[+] This is a single-party task: %s\n", method);

  eigen_t *context = eigen_context_new(g_enclave_info, uid, token,
                                       (struct sockaddr *)&tms_addr);
  if (context == NULL) {
    return EXIT_FAILURE;
  }

  eigen_task_t *task = eigen_create_task(context, method);
  if (task == NULL) {
    return EXIT_FAILURE;
  }
  printf("args: %s, size=%lu\n", args, strlen(args));
  // BUG result truncating
  ret = eigen_task_invoke_with_payload(task, args, strlen(args), recvbuf,
                                       sizeof(recvbuf));
  if (ret <= 0) {
    return EXIT_FAILURE;
  }

  printf("Response: %s\n", recvbuf);
  *output_size = strlen(recvbuf);
  *output = (char *)malloc(strlen(recvbuf) + 1);
  memset(*output, 0, *output_size);
  memcpy(*output, recvbuf, *output_size);

  eigen_task_free(task);
  eigen_context_free(context);
  return 0;
}

int init(const char *pub, const char *pri, const char *conf, int32_t port1) {
  eigen_init();

  g_auditors = eigen_auditor_set_new();
  eigen_auditor_set_add_auditor(g_auditors, pub, pri);

  if (g_auditors == NULL) {
    return EXIT_FAILURE;
  }

  g_enclave_info = eigen_enclave_info_load(g_auditors, conf);

  if (g_enclave_info == NULL) {
    return EXIT_FAILURE;
  }
  g_tms_port = port1;

  return 0;
}

int release() {
  eigen_enclave_info_free(g_enclave_info);
  eigen_auditor_set_free(g_auditors);
  return 0;
}