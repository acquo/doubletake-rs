#include <stdio.h>
#include <windows.h>
#include <d3d11.h>
#include "nvEncodeAPI.h"

static void try_cfg(NV_ENCODE_API_FUNCTION_LIST* fn, void* enc, NV_ENC_CONFIG* cfg, const char* label) {
    NV_ENC_INITIALIZE_PARAMS init = { 0 };
    init.version = NV_ENC_INITIALIZE_PARAMS_VER;
    init.encodeGUID = NV_ENC_CODEC_H264_GUID;
    init.presetGUID = NV_ENC_PRESET_P4_GUID;
    init.encodeWidth = 1920;
    init.encodeHeight = 1080;
    init.darWidth = 1920;
    init.darHeight = 1080;
    init.frameRateNum = 30;
    init.frameRateDen = 1;
    init.enablePTD = 1;
    init.enableEncodeAsync = 1;
    init.maxEncodeWidth = 1920;
    init.maxEncodeHeight = 1080;
    init.tuningInfo = NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY;
    init.encodeConfig = cfg;
    NVENCSTATUS s = fn->nvEncInitializeEncoder(enc, &init);
    printf("  %s: 0x%x\n", label, s);
}

int main(void) {
    HMODULE dll = LoadLibraryA("nvEncodeAPI64.dll");
    typedef NVENCSTATUS (NVENCAPI *CreateFn)(NV_ENCODE_API_FUNCTION_LIST*);
    CreateFn create = (CreateFn)GetProcAddress(dll, "NvEncodeAPICreateInstance");
    NV_ENCODE_API_FUNCTION_LIST fn = { 0 };
    fn.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    create(&fn);
    ID3D11Device* device = NULL;
    D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };
    D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 1, D3D11_SDK_VERSION, &device, NULL, NULL);
    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS open = { 0 };
    open.version = NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
    open.device = device;
    open.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    open.apiVersion = NVENCAPI_VERSION;
    void* enc = NULL;
    fn.nvEncOpenEncodeSessionEx(&open, &enc);
    printf("session ok\n");

    NV_ENC_CONFIG c1 = { 0 }; c1.version = NV_ENC_CONFIG_VER;
    try_cfg(&fn, enc, &c1, "version only");

    NV_ENC_CONFIG c2 = { 0 }; c2.version = NV_ENC_CONFIG_VER; c2.profileGUID = NV_ENC_H264_PROFILE_BASELINE_GUID;
    try_cfg(&fn, enc, &c2, "+profileGUID");

    NV_ENC_CONFIG c3 = c2; c3.gopLength = 30;
    try_cfg(&fn, enc, &c3, "+gopLength");

    NV_ENC_CONFIG c4 = c3; c4.frameIntervalP = 1;
    try_cfg(&fn, enc, &c4, "+frameIntervalP");

    NV_ENC_CONFIG c5 = c4; c5.rcParams.version = NV_ENC_RC_PARAMS_VER; c5.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CONSTQP;
    try_cfg(&fn, enc, &c5, "+rcParams(CONSTQP)");

    NV_ENC_CONFIG c6 = c5; c6.rcParams.averageBitRate = 8000000; c6.rcParams.maxBitRate = 8000000;
    try_cfg(&fn, enc, &c6, "+bitrate");

    NV_ENC_CONFIG c7 = c6; c7.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CBR;
    try_cfg(&fn, enc, &c7, "CBR");
    return 0;
}
