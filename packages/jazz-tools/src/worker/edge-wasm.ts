// InitWasm allow to load the wasm code in edge runtimes (ex. cloudflare worker and vercel edge functions)
import { init as InitWasm, initSync } from "cojson/node/WasmNode/edge";
import { WasmNode } from "cojson/node/WasmNode";

WasmNode.setInit(InitWasm);
WasmNode.setInitSync(initSync);
