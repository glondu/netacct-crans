(***************************************************************************)
(*  Copyright (C) 2009 Stephane Glondu <steph@glondu.net>                  *)
(*                                                                         *)
(*  This program is free software: you can redistribute it and/or modify   *)
(*  it under the terms of the GNU General Public License as published by   *)
(*  the Free Software Foundation, either version 3 of the License, or (at  *)
(*  your option) any later version, with the additional exemption that     *)
(*  compiling, linking, and/or using OpenSSL is allowed.                   *)
(*                                                                         *)
(*  This program is distributed in the hope that it will be useful, but    *)
(*  WITHOUT ANY WARRANTY; without even the implied warranty of             *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      *)
(*  Affero General Public License for more details.                        *)
(*                                                                         *)
(*  You should have received a copy of the GNU Affero General Public       *)
(*  License along with this program.  If not, see                          *)
(*  <http://www.gnu.org/licenses/>.                                        *)
(***************************************************************************)

open Printf
(*open CalendarLib*)

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

let pq_now () =
  let chan = Unix.open_process_in "date +\"TIMESTAMP '%Y-%m-%d %T'\"" in
  let r = input_line chan in
  match Unix.close_process_in chan with
    | Unix.WEXITED 0 -> r
    | _ -> failwith "unexpected return of date"

(*
let format_date_for_pq x = Printer.Calendar.sprint "TIMESTAMP '%Y-%m-%d %T'" x
let pq_now () = format_date_for_pq (Calendar.now ())
*)

let format_ipv4 x =
  let (&&) = Int32.logand and (>>) = Int32.shift_right_logical in
  let a = (x && 0xff000000l) >> 24 in
  let b = (x && 0xff0000l) >> 16 in
  let c = (x && 0xff00l) >> 8 in
  let d = x && 0xffl in
  sprintf "%ld.%ld.%ld.%ld" a b c d

let string_of_peers = function
  | IPv4 (a, b) ->
      sprintf "%s -> %s" (format_ipv4 a) (format_ipv4 b)
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
  flush chan;
  Hashtbl.clear ht;
  if signal = Sys.sigterm then (eprintf "dying\n%!"; Pcap.pcap_breakloop h) else ()

let is_crans_ipv4 a =
  let x = Int32.logand a 0xfffff800l in (* /21 *)
  x = 0x8ae78800l (* 138.231.136.0 *) || x = 0x8ae79000l (* 138.231.144.0 *)

let is_crans_ipv6 (a, _) =
  let x = Int64.logand a 0xffffffffffff0000L in (* /48 *)
  x = 0x2a010240fe3d0000L (* 2a01:240:fe3d:: *)

let capture chan =
  let h = Pcap.pcap_open_live "ens" 128 0 1000 in
  let ht = Hashtbl.create 1024 in
  let last_ts = ref 0 in
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
         let cumul =
           try
             let size0 = Hashtbl.find ht key in
             let cumul = size0+size in
             Hashtbl.replace ht key cumul; cumul
           with Not_found ->
             Hashtbl.add ht key size; size
         in
         let ts = hdr.Pcap.ts.Pcap.tv_sec in
         (* 5 minutes or 200 MB *)
         if ts - !last_ts >= 300 || cumul >= 200*1024*1024 then
           (flush h ht chan Sys.sigusr1; last_ts := ts)
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
  printf "===> Received dump of size %d\n"  (Hashtbl.length ht);
  let all_values = ref [] in
  (* Top 3 *)
  Hashtbl.iter (fun k v -> all_values := (k, v)::!all_values) ht;
  all_values := List.sort (fun (_, v1) (_, v2) -> v2-v1) !all_values;
  (match !all_values with
     | a::b::c::_ -> all_values := [a; b; c]
     | _ -> ());
  List.iter
    (fun ((peers, _), size) -> printf "%s: %d bytes\n" (string_of_peers peers) size)
    !all_values;
  (* Inject into SQL database *)
  let pq = new Postgresql.connection ~host:"pgsql.adm.crans.org" ~user:"crans" ~dbname:"netacct-ng" () in
  let ts = pq_now () in
  Hashtbl.iter
    (fun k v ->
       try
         (match k with
            | (IPv4 (a, b), proto, sport, dport) ->
                let (ip_crans, port_crans, ip_ext, port_ext, download, upload) =
                  if is_crans_ipv4 a then (a, sport, b, dport, 0, v)
                  else if is_crans_ipv4 b then (b, dport, a, sport, v, 0)
                  else
                    (eprintf "Traffic between unknown IP addresses: %s -> %s" (format_ipv4 a) (format_ipv4 b);
                     raise Not_found)
                in
                let query =
                  "INSERT INTO upload (date, ip_crans, ip_ext, proto, port_crans, port_ext, download, upload)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8);"
                in
                let expect = [Postgresql.Command_ok] in
                let params = [|ts;
                               format_ipv4 ip_crans;
                               format_ipv4 ip_ext;
                               string_of_int proto;
                               string_of_int port_crans;
                               string_of_int port_ext;
                               string_of_int download;
                               string_of_int upload|] in
                ignore (pq#exec ~expect ~params query)
            | (IPv6 (_, _), _, _, _) -> (* we ignore for now *)
                ())
       with Not_found -> (* a warning has been issued *)
         ())
    ht;
  pq#finish;
  printf "<=== End of dump\n%!";
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
