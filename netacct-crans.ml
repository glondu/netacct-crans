(*
  Compile with:
  ocamlfind ocamlopt -package pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg pcap_test.ml
*)

open Printf

let flush_interval = 0.5
let starting_time = Unix.gettimeofday ()

type peers =
  | IPv4 of int32 * int32
  | IPv6 of (int64 * int64) * (int64 * int64)

type error =
  | Invalid_Ethernet
  | Invalid_IPv4
  | Invalid_IPv6
  | Unknown_ethertype of int

exception Error of error

let error x = raise (Error x)

let (input_ht : in_channel -> 'a), (output_ht : out_channel -> 'a -> unit) =
  input_value, output_value

let string_of_error = function
  | Invalid_Ethernet -> "invalid ethernet frame"
  | Invalid_IPv4 -> "invalid IPv4 frame"
  | Invalid_IPv6 -> "invalid IPv6 frame"
  | Unknown_ethertype i -> sprintf "unknown ethertype (0x%x)" i

let string_of_peers = function
  | IPv4 (a, b) ->
      sprintf "0x%08lx -> 0x%08lx" a b
  | IPv6 ((a1, a2), (b1, b2)) ->
      sprintf "0x%016Lx%016Lx -> 0x%016Lx%016Lx" a1 a2 b1 b2

let string_of_proto = function
  | ((1 | 58), typ, code) -> sprintf "ICMP (%d, %d)" typ code
  | (17, s, d) -> sprintf "UDP (%d -> %d)" s d
  | (6, s, d) -> sprintf "TCP (%d -> %d)" s d
  | (p, _, _) -> sprintf "Unknown (%d)" p


let parse_payload is_ipv4 proto payload = match proto with
  | 6 (* TCP *) | 17 (* UDP *) ->
      (bitmatch payload with
         | { sport : 16; dport : 16 } -> (proto, sport, dport)
         | { } -> (proto, 0, 0))
  | _ when proto = (if is_ipv4 then 1 else 58) (* ICMP *) ->
      (bitmatch payload with
         | { typ : 8; code : 8 } -> (proto, typ, code)
         | { } -> (proto, 0, 0))
  | _ -> (proto, 0, 0)


let parse_ether ethertype payload = match ethertype with
  | 0x0800 (* IPv4 *) ->
      (bitmatch payload with
         | { 4 : 4; ihl : 4; _ : 8; len : 16; _ : 32;
             _ : 8; proto : 8; _ : 16;
             src : 32; dst : 32;
             _ : ihl*32 : bitstring;
             payload : -1 : bitstring } ->
             (* IHL should be >= 5 but seems to be = 0 in practice *)
             if ihl <> 0 then eprintf "IHL=%d found\n%!" ihl;
             ((IPv4 (src, dst),
               parse_payload true proto payload), len)
         | { } -> error Invalid_IPv4)
  | 0x86dd (* IPv6 *) ->
      (bitmatch payload with
         | { 6 : 4; _ : 28; len : 16; proto : 8; _ : 8;
             src1 : 64; src2 : 64; dst1 : 64; dst2 : 64;
             payload : -1 : bitstring } ->
             ((IPv6 ((src1, src2), (dst1, dst2)),
               parse_payload false proto payload), len)
         | { } -> error Invalid_IPv6)
  | x -> error (Unknown_ethertype x)


let flush h ht chan signal =
  let now = Unix.gettimeofday () in
  printf "================================================== %g \n%!" (now -. starting_time);
  output_ht chan ht;
  Hashtbl.clear ht;
  if signal = Sys.sigterm then (eprintf "dying\n%!"; Pcap.pcap_breakloop h) else ()


let capture chan =
  let h = Pcap.pcap_open_live "eth0" 128 0 1000 in
  let ht = Hashtbl.create 1024 in
  let counter = ref 0 in
  let sig_handler = Sys.Signal_handle (flush h ht chan) in
  let () = Sys.set_signal Sys.sigusr1 sig_handler in
  let () = Sys.set_signal Sys.sigterm sig_handler in
  let r = Pcap.pcap_loop h (-1)
    (fun _ hdr data ->
       let data = data, 0, hdr.Pcap.caplen lsl 3 in (* dark magic! *)
       try
         let (key, size) =
           (bitmatch data with
              | { _ : 48; _ : 48; ethertype : 16; payload : -1 : bitstring } ->
                  parse_ether ethertype payload)
         in
         (try
            let size0 = Hashtbl.find ht key in
            Hashtbl.replace ht key (size0+size)
          with Not_found ->
            Hashtbl.add ht key size);
         incr counter;
         if !counter >= 100 then (flush h ht chan Sys.sigusr1; counter := 0);
       with
         | Error (Unknown_ethertype 0x806) (* ARP *) -> ()
         | Error e ->
             eprintf "W: %s\n%!" (string_of_error e)
         | Match_failure _ ->
             eprintf "W: invalid frame (caplen=%d)\n%!" hdr.Pcap.caplen;
             Bitstring.hexdump_bitstring stderr data;
             eprintf "%!"
    ) ""
  in eprintf "pcap_loop exited with code %d\n%!" r; (match r with
        | 0 | -2 -> ()
        | -1 -> Pcap.pcap_perror h "netacct-ng"
        | x -> eprintf "W: unknown return value of pcap_loop: %d\n%!" x);
  Pcap.pcap_close h


let rec inject chan =
  let ht = input_ht chan in
  printf "Received hash table of size %d\n%!"  (Hashtbl.length ht);
  inject chan

let () =
  let inc, outc = Unix.pipe () in
  let inc, outc = Unix.in_channel_of_descr inc, Unix.out_channel_of_descr outc in
  let pid = Unix.fork () in
  if pid <> 0 then (
    close_in inc;
    capture outc
  ) else (
    close_out outc;
    Sys.set_signal Sys.sigusr1 Sys.Signal_ignore;
    inject inc
  )
