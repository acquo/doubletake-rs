// Decisive probe: same calls in C with the same 13.0 header.
#include <stdio.h>
#include <windows.h>
#include <d3d11.h>
#include "nvEncodeAPI.h"

int main(void) {
    HMODULE dll = LoadLibraryA("nvEncodeAPI64.dll");
    if (!dll) { printf("load dll failed\n"); return 1; }
    typedef NVENCSTATUS (NVENCAPI *CreateFn)(NV_ENCODE_API_FUNCTION_LIST*);
    CreateFn create = (CreateFn)GetProcAddress(dll, "NvEncodeAPICreateInstance");
    NV_ENCODE_API_FUNCTION_LIST fn = { 0 };
    fn.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    NVENCSTATUS s = create(&fn);
    printf("create: 0x%x\n", s);

    uint32_t maxv = 0;
    typedef NVENCSTATUS (NVENCAPI *MaxVerFn)(uint32_t*);
    MaxVerFn maxver = (MaxVerFn)GetProcAddress(dll, "NvEncodeAPIGetMaxSupportedVersion");
    maxver(&maxv);
    printf("driver max: major=%u minor=%u\n", maxv >> 4, maxv & 0xf);

    // D3D11 device
    ID3D11Device* device = NULL;
    D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };
    HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 1, D3D11_SDK_VERSION, &device, NULL, NULL);
    if (FAILED(hr)) { printf("d3d11 create failed 0x%08x\n", hr); return 1; }
    printf("d3d11 device ok\n");

    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS open = { 0 };
    open.version = NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
    open.device = device;
    open.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    open.apiVersion = NVENCAPI_VERSION;
    void* enc = NULL;
    s = fn.nvEncOpenEncodeSessionEx(&open, &enc);
    printf("open session: 0x%x enc=%p\n", s, enc);
    if (s != NV_ENC_SUCCESS) return 1;

    NV_ENC_PRESET_CONFIG pc = { 0 };
    pc.version = NV_ENC_PRESET_CONFIG_VER;
    pc.presetCfg.version = NV_ENC_CONFIG_VER;
    s = fn.nvEncGetEncodePresetConfig(enc, NV_ENC_CODEC_H264_GUID, NV_ENC_PRESET_P4_GUID, &pc);
    printf("preset config: 0x%x\n", s);

    // Input formats supported for H.264 on this session.
    {
        uint32_t fmt_count = 0;
        s = fn.nvEncGetInputFormatCount(enc, NV_ENC_CODEC_H264_GUID, &fmt_count);
        printf("input format count: 0x%x -> %u\n", s, fmt_count);
        if (s == NV_ENC_SUCCESS && fmt_count > 0) {
            NV_ENC_BUFFER_FORMAT* fmts = (NV_ENC_BUFFER_FORMAT*)malloc(fmt_count * sizeof(NV_ENC_BUFFER_FORMAT));
            s = fn.nvEncGetInputFormats(enc, NV_ENC_CODEC_H264_GUID, fmts, fmt_count, &fmt_count);
            printf("input formats: 0x%x -> ", s);
            for (uint32_t i = 0; i < fmt_count; i++) printf("0x%x ", fmts[i]);
            printf("\n");
            free(fmts);
        }
    }

    NV_ENC_CONFIG config = pc.presetCfg;
    config.version = NV_ENC_CONFIG_VER;
    config.profileGUID = NV_ENC_H264_PROFILE_BASELINE_GUID;
    config.gopLength = 30;
    config.frameIntervalP = 1;
    config.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CBR;
    config.rcParams.averageBitRate = 8000000;
    config.rcParams.maxBitRate = 8000000;
    config.rcParams.vbvBufferSize = 8000000;
    config.rcParams.vbvInitialDelay = 8000000;

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
    init.encodeConfig = &config;
    s = fn.nvEncInitializeEncoder(enc, &init);
    printf("init: 0x%x\n", s);
    return 0;
}
