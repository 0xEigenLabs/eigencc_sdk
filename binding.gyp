{
    "targets": [
        {
            "target_name": "tee_task",
            "cflags!": ["-fno-exceptions"],
            "cflags_cc!": ["-fno-exceptions"],
            "defines": ["NAPI_CPP_EXCEPTIONS"],
            "sources": ["tee_task/*.cc", "tee_task/*.h" ],
            "include_dirs": [
                "<!@(node -p \"require('node-addon-api').include\")"
            ],
            "libraries": ["<(module_root_dir)/deps/libsdk_c.so"]
        }
    ]
}
