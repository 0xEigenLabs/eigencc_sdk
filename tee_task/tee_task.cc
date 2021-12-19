#include <iostream>
#include <fstream>
#include <string>

#include <netdb.h>

#include <napi.h>

#include "include/eigentee.h"
#include "include/tee_task.h"

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
    return EXIT_FAILURE;
  }

  if (!hptr->h_addr_list[0]) {
    return EXIT_FAILURE;
  }

  tms_addr.sin_family = AF_INET;
  tms_addr.sin_addr.s_addr = *(u_long *)hptr->h_addr_list[0];
  tms_addr.sin_port = htons(g_tms_port);

  eigen_t *context = eigen_context_new(g_enclave_info, uid, token,
                                       (struct sockaddr *)&tms_addr);
  if (context == NULL) {
    return EXIT_FAILURE;
  }

  eigen_task_t *task = eigen_create_task(context, method);
  if (task == NULL) {
    return EXIT_FAILURE;
  }

  // BUG result truncating
  ret = eigen_task_invoke_with_payload(task, args, strlen(args), recvbuf,
                                       sizeof(recvbuf));
  if (ret <= 0) {
    return EXIT_FAILURE;
  }

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

static bool is_file_exist(Napi::String fileName) {
  std::ifstream infile(std::string(fileName).c_str());
  return infile.good();
}

Napi::Value Init(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() != 4) {
    Napi::TypeError::New(env, "Wrong number of arguments (expect 4)")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsString() || !info[1].IsString() || !info[2].IsString() ||
      !info[3].IsNumber()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::String pub = info[0].As<Napi::String>();
  Napi::String pri = info[1].As<Napi::String>();
  Napi::String conf = info[2].As<Napi::String>();
  int32_t port1 = info[3].As<Napi::Number>().Int32Value();

  if (g_enclave_info && g_auditors) {
    // Already init
    return Napi::Number::New(env, 0);
  }

  // If env is set with invalid value, fast failue
  // Just check the file exists
  if (!is_file_exist(pub)){
        Napi::TypeError::New(env, std::string("Pub File do not exist: ") + std::string(pub))
        .ThrowAsJavaScriptException();
    return env.Null();

  }

    if (!is_file_exist(pri)){
        Napi::TypeError::New(env, std::string("Pri File do not exist: ") + std::string(pri))
        .ThrowAsJavaScriptException();
    return env.Null();

  }


  if (!is_file_exist(conf)){
        Napi::TypeError::New(env, std::string("Conf File do not exist: ") + std::string(conf))
        .ThrowAsJavaScriptException();
    return env.Null();

  }


  int result = init(std::string(pub).c_str(), std::string(pri).c_str(),
                    std::string(conf).c_str(), port1);
  return Napi::Number::New(env, result);
}

Napi::Value Release(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() != 0) {
    Napi::TypeError::New(env, "Wrong number of arguments (expect 0)")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  int result = release();
  return Napi::Number::New(env, result);
}

Napi::Value SubmitTask(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  if (info.Length() != 4) {
    Napi::TypeError::New(env, "Wrong number of arguments (expect 4)")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsString() || !info[1].IsString() || !info[2].IsString() ||
      !info[3].IsString()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!g_enclave_info || !g_auditors) {
    // Not init
    Napi::TypeError::New(env, "Not init yet").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::String method = info[0].As<Napi::String>();
  Napi::String args = info[1].As<Napi::String>();
  Napi::String uid = info[2].As<Napi::String>();
  Napi::String token = info[3].As<Napi::String>();

  char *output = NULL; // malloc from `submit_task`
  size_t output_size = 0;

  int result = submit_task(std::string(method).c_str(),
                           std::string(args).c_str(), std::string(uid).c_str(),
                           std::string(token).c_str(), &output, &output_size);

  if (result != 0) {
    if (output) {
      free(output);
      output = NULL;
    }
    Napi::TypeError::New(env, "Fail to submit task")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::String ret = Napi::String::New(env, output, output_size);

  if (output) {
    free(output);
    output = NULL;
  }

  return ret;
}

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "init"), Napi::Function::New(env, Init));
  exports.Set(Napi::String::New(env, "release"),
              Napi::Function::New(env, Release));
  exports.Set(Napi::String::New(env, "submit_task"),
              Napi::Function::New(env, SubmitTask));
  return exports;
}

NODE_API_MODULE(tee_task, InitModule)