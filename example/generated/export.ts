/**
 *
 * This file is auto-generated. Do not edit manually: changes may be erased.
 * Generated by Aqua compiler: https://github.com/fluencelabs/aqua/. 
 * If you find any bugs, please write an issue on GitHub: https://github.com/fluencelabs/aqua/issues
 * Aqua version: 0.3.1-228
 *
 */
import { Fluence, FluencePeer } from '@fluencelabs/fluence';
import {
    ResultCodes,
    RequestFlow,
    RequestFlowBuilder,
    CallParams,
} from '@fluencelabs/fluence/dist/internal/compilerSupport/v1';


// Services


// Functions

 export function verify_trust(node: string, trust: {expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}, issuer_peer_id: string, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function verify_trust(peer: FluencePeer, node: string, trust: {expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}, issuer_peer_id: string, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function verify_trust(...args: any) {
     let peer: FluencePeer;
     let node: any;
let trust: any;
let issuer_peer_id: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
trust = args[2];
issuer_peer_id = args[3];
config = args[4];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
trust = args[1];
issuer_peer_id = args[2];
config = args[3];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;success:boolean}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (seq
        (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
        (call %init_peer_id% ("getDataSrv" "node") [] node)
       )
       (call %init_peer_id% ("getDataSrv" "trust") [] trust)
      )
      (call %init_peer_id% ("getDataSrv" "issuer_peer_id") [] issuer_peer_id)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (seq
      (call node ("peer" "timestamp_sec") [] timestamp_sec)
      (call node ("trust-graph" "verify_trust") [trust issuer_peer_id timestamp_sec] result)
     )
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'trust', () => {return trust;});
h.on('getDataSrv', 'issuer_peer_id', () => {return issuer_peer_id;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for verify_trust');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function issue_trust(node: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number, trust_bytes: number[], config?: {ttl?: number}) : Promise<{error:string;success:boolean;trust:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}}>;
 export function issue_trust(peer: FluencePeer, node: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number, trust_bytes: number[], config?: {ttl?: number}) : Promise<{error:string;success:boolean;trust:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}}>;
 export function issue_trust(...args: any) {
     let peer: FluencePeer;
     let node: any;
let issued_for_peer_id: any;
let expires_at_sec: any;
let issued_at_sec: any;
let trust_bytes: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
issued_for_peer_id = args[2];
expires_at_sec = args[3];
issued_at_sec = args[4];
trust_bytes = args[5];
config = args[6];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
issued_for_peer_id = args[1];
expires_at_sec = args[2];
issued_at_sec = args[3];
trust_bytes = args[4];
config = args[5];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;success:boolean;trust:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (seq
        (seq
         (seq
          (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
          (call %init_peer_id% ("getDataSrv" "node") [] node)
         )
         (call %init_peer_id% ("getDataSrv" "issued_for_peer_id") [] issued_for_peer_id)
        )
        (call %init_peer_id% ("getDataSrv" "expires_at_sec") [] expires_at_sec)
       )
       (call %init_peer_id% ("getDataSrv" "issued_at_sec") [] issued_at_sec)
      )
      (call %init_peer_id% ("getDataSrv" "trust_bytes") [] trust_bytes)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (call node ("trust-graph" "issue_trust") [issued_for_peer_id expires_at_sec issued_at_sec trust_bytes] result)
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'issued_for_peer_id', () => {return issued_for_peer_id;});
h.on('getDataSrv', 'expires_at_sec', () => {return expires_at_sec;});
h.on('getDataSrv', 'issued_at_sec', () => {return issued_at_sec;});
h.on('getDataSrv', 'trust_bytes', () => {return trust_bytes;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for issue_trust');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function insert_cert(node: string, certificate: {chain:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}[]}, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function insert_cert(peer: FluencePeer, node: string, certificate: {chain:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}[]}, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function insert_cert(...args: any) {
     let peer: FluencePeer;
     let node: any;
let certificate: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
certificate = args[2];
config = args[3];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
certificate = args[1];
config = args[2];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;success:boolean}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
       (call %init_peer_id% ("getDataSrv" "node") [] node)
      )
      (call %init_peer_id% ("getDataSrv" "certificate") [] certificate)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (seq
      (call node ("peer" "timestamp_sec") [] timestamp_sec)
      (call node ("trust-graph" "insert_cert") [certificate timestamp_sec] result)
     )
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'certificate', () => {return certificate;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for insert_cert');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function get_all_certs(node: string, issued_for: string, config?: {ttl?: number}) : Promise<{certificates:{chain:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}[]}[];error:string;success:boolean}>;
 export function get_all_certs(peer: FluencePeer, node: string, issued_for: string, config?: {ttl?: number}) : Promise<{certificates:{chain:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}[]}[];error:string;success:boolean}>;
 export function get_all_certs(...args: any) {
     let peer: FluencePeer;
     let node: any;
let issued_for: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
issued_for = args[2];
config = args[3];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
issued_for = args[1];
config = args[2];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{certificates:{chain:{expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}[]}[];error:string;success:boolean}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
       (call %init_peer_id% ("getDataSrv" "node") [] node)
      )
      (call %init_peer_id% ("getDataSrv" "issued_for") [] issued_for)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (seq
      (call node ("peer" "timestamp_sec") [] timestamp_sec)
      (call node ("trust-graph" "get_all_certs") [issued_for timestamp_sec] result)
     )
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'issued_for', () => {return issued_for;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for get_all_certs');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function add_trust(node: string, trust: {expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}, issuer_peer_id: string, config?: {ttl?: number}) : Promise<{error:string;success:boolean;weight:number}>;
 export function add_trust(peer: FluencePeer, node: string, trust: {expires_at:number;issued_at:number;issued_for:string;sig_type:string;signature:string}, issuer_peer_id: string, config?: {ttl?: number}) : Promise<{error:string;success:boolean;weight:number}>;
 export function add_trust(...args: any) {
     let peer: FluencePeer;
     let node: any;
let trust: any;
let issuer_peer_id: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
trust = args[2];
issuer_peer_id = args[3];
config = args[4];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
trust = args[1];
issuer_peer_id = args[2];
config = args[3];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;success:boolean;weight:number}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (seq
        (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
        (call %init_peer_id% ("getDataSrv" "node") [] node)
       )
       (call %init_peer_id% ("getDataSrv" "trust") [] trust)
      )
      (call %init_peer_id% ("getDataSrv" "issuer_peer_id") [] issuer_peer_id)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (seq
      (call node ("peer" "timestamp_sec") [] timestamp_sec)
      (call node ("trust-graph" "add_trust") [trust issuer_peer_id timestamp_sec] result)
     )
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'trust', () => {return trust;});
h.on('getDataSrv', 'issuer_peer_id', () => {return issuer_peer_id;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for add_trust');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function add_root(node: string, peer_id: string, weight_factor: number, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function add_root(peer: FluencePeer, node: string, peer_id: string, weight_factor: number, config?: {ttl?: number}) : Promise<{error:string;success:boolean}>;
 export function add_root(...args: any) {
     let peer: FluencePeer;
     let node: any;
let peer_id: any;
let weight_factor: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
peer_id = args[2];
weight_factor = args[3];
config = args[4];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
peer_id = args[1];
weight_factor = args[2];
config = args[3];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;success:boolean}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (seq
        (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
        (call %init_peer_id% ("getDataSrv" "node") [] node)
       )
       (call %init_peer_id% ("getDataSrv" "peer_id") [] peer_id)
      )
      (call %init_peer_id% ("getDataSrv" "weight_factor") [] weight_factor)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (call node ("trust-graph" "add_root") [peer_id weight_factor] result)
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'peer_id', () => {return peer_id;});
h.on('getDataSrv', 'weight_factor', () => {return weight_factor;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for add_root');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function get_weight(node: string, peer_id: string, config?: {ttl?: number}) : Promise<{error:string;peer_id:string;success:boolean;weight:number}>;
 export function get_weight(peer: FluencePeer, node: string, peer_id: string, config?: {ttl?: number}) : Promise<{error:string;peer_id:string;success:boolean;weight:number}>;
 export function get_weight(...args: any) {
     let peer: FluencePeer;
     let node: any;
let peer_id: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
peer_id = args[2];
config = args[3];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
peer_id = args[1];
config = args[2];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;peer_id:string;success:boolean;weight:number}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
       (call %init_peer_id% ("getDataSrv" "node") [] node)
      )
      (call %init_peer_id% ("getDataSrv" "peer_id") [] peer_id)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (seq
      (call node ("peer" "timestamp_sec") [] timestamp_sec)
      (call node ("trust-graph" "get_weight") [peer_id timestamp_sec] result)
     )
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'peer_id', () => {return peer_id;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for get_weight');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      


 export function get_trust_bytes(node: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number, config?: {ttl?: number}) : Promise<{error:string;result:number[];success:boolean}>;
 export function get_trust_bytes(peer: FluencePeer, node: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number, config?: {ttl?: number}) : Promise<{error:string;result:number[];success:boolean}>;
 export function get_trust_bytes(...args: any) {
     let peer: FluencePeer;
     let node: any;
let issued_for_peer_id: any;
let expires_at_sec: any;
let issued_at_sec: any;
     let config: any;
     if (FluencePeer.isInstance(args[0])) {
         peer = args[0];
         node = args[1];
issued_for_peer_id = args[2];
expires_at_sec = args[3];
issued_at_sec = args[4];
config = args[5];
     } else {
         peer = Fluence.getPeer();
         node = args[0];
issued_for_peer_id = args[1];
expires_at_sec = args[2];
issued_at_sec = args[3];
config = args[4];
     }
    
     let request: RequestFlow;
     const promise = new Promise<{error:string;result:number[];success:boolean}>((resolve, reject) => {
         const r = new RequestFlowBuilder()
                 .disableInjections()
                 .withRawScript(
                     `
     (xor
 (seq
  (seq
   (seq
    (seq
     (seq
      (seq
       (seq
        (seq
         (call %init_peer_id% ("getDataSrv" "-relay-") [] -relay-)
         (call %init_peer_id% ("getDataSrv" "node") [] node)
        )
        (call %init_peer_id% ("getDataSrv" "issued_for_peer_id") [] issued_for_peer_id)
       )
       (call %init_peer_id% ("getDataSrv" "expires_at_sec") [] expires_at_sec)
      )
      (call %init_peer_id% ("getDataSrv" "issued_at_sec") [] issued_at_sec)
     )
     (call -relay- ("op" "noop") [])
    )
    (xor
     (call node ("trust-graph" "get_trust_bytes") [issued_for_peer_id expires_at_sec issued_at_sec] result)
     (seq
      (call -relay- ("op" "noop") [])
      (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 1])
     )
    )
   )
   (call -relay- ("op" "noop") [])
  )
  (xor
   (call %init_peer_id% ("callbackSrv" "response") [result])
   (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 2])
  )
 )
 (call %init_peer_id% ("errorHandlingSrv" "error") [%last_error% 3])
)

                 `,
                 )
                 .configHandler((h) => {
                     h.on('getDataSrv', '-relay-', () => {
                    return peer.getStatus().relayPeerId;
                });
                h.on('getDataSrv', 'node', () => {return node;});
h.on('getDataSrv', 'issued_for_peer_id', () => {return issued_for_peer_id;});
h.on('getDataSrv', 'expires_at_sec', () => {return expires_at_sec;});
h.on('getDataSrv', 'issued_at_sec', () => {return issued_at_sec;});
                h.onEvent('callbackSrv', 'response', (args) => {
    const [res] = args;
  resolve(res);
});

                h.onEvent('errorHandlingSrv', 'error', (args) => {
                    const [err] = args;
                    reject(err);
                });
            })
            .handleScriptError(reject)
            .handleTimeout(() => {
                reject('Request timed out for get_trust_bytes');
            })
        if(config && config.ttl) {
            r.withTTL(config.ttl)
        }
        request = r.build();
    });
    peer.internals.initiateFlow(request!);
    return promise;
}
      
