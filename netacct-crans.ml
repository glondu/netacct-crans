(***************************************************************************)
(*  Copyright (C) 2009-2010 Stephane Glondu <steph@glondu.net>             *)
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
(*  General Public License for more details.                               *)
(*                                                                         *)
(*  You should have received a copy of the GNU General Public License      *)
(*  along with this program.  If not, see <http://www.gnu.org/licenses/>.  *)
(***************************************************************************)

open Printf

(* The following code doesn't work (segfault) on komaz for an unknown reason:
open CalendarLib
let format_date_for_pq x = Printer.Calendar.sprint "%Y-%m-%d %T" x
let pq_now () = format_date_for_pq (Calendar.now ())
*)

let pq_now () =
  let chan = Unix.open_process_in "date +'%Y-%m-%d %T'" in
  let r = input_line chan in
  match Unix.close_process_in chan with
    | Unix.WEXITED 0 -> r
    | _ -> failwith "unexpected return of date"

let starting_time = Unix.gettimeofday ()
let formatted_starting_time = pq_now ()

let newline_re = Str.regexp "[ \t]*\n[ \t]*"

(** Command line handling *)
module Clflags = struct
  let interface = ref "ens"
  let daemonize = ref false
  let debug = ref 3
  let pidfile = ref None
  let syslog = ref false

  let process = ref "netacct-crans"
  let skip_header = ref 0

  let cmdline_spec = [
    "-b", Arg.Set daemonize, " Go to background";
    "-I", Arg.Set_string interface, sprintf "<interface>  Capturing interface (default: %s)" !interface;
    "-d", Arg.Set_int debug, sprintf "<n>  Debugging level (default: %d)" !debug;
    "-p", Arg.String (fun x -> pidfile := Some x), "<pidfile>  Write master PID to file (default: none)";
    "--force-syslog", Arg.Set syslog, " Force syslog even when running in foreground mode";
  ]

  let anonfun s =
    raise (Arg.Bad (sprintf "do not know what to do with %s" s))

  let usage_msg =
    sprintf "%s [options]" Sys.argv.(0)

  let () =
    Arg.parse cmdline_spec anonfun usage_msg;
    if !daemonize then syslog := true
end

(* from now on, arguments are supposed to be parsed *)

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

let level_of_int : int -> Syslog.level = function
  | 0 -> `LOG_ERR
  | 1 -> `LOG_WARNING
  | 2 -> `LOG_NOTICE
  | 3 -> `LOG_INFO
  | 4 -> `LOG_DEBUG
  | _ -> raise Exit

let dummy_debug fmt = ksprintf (fun _ -> ()) fmt

let debug level fmt =
  ksprintf begin fun msg ->
    if level <= !Clflags.debug then begin
      if !Clflags.syslog then begin
        (* syslog-ng seems to flush logs only once per
           openlog/closelog, so we call them each time *)
        try
          let level = level_of_int level in
          let h = Syslog.openlog ~facility:`LOG_DAEMON !Clflags.process in
          Syslog.syslog h level msg;
          Syslog.closelog h
        with Exit -> (* level not logged with syslog *)
          ()
      end;
      printf "%d: " level;
      print_endline msg
    end else ()
  end fmt

let format_ipv4 x =
  let (&&) = Int32.logand and (>>) = Int32.shift_right_logical in
  let a = (x && 0xff000000l) >> 24 in
  let b = (x && 0xff0000l) >> 16 in
  let c = (x && 0xff00l) >> 8 in
  let d = x && 0xffl in
  sprintf "%ld.%ld.%ld.%ld" a b c d

let format_ipv6 (x, y) =
  let (&&) = Int64.logand and (>>) = Int64.shift_right_logical in
  let a = (x && 0xffff000000000000L) >> 48 in
  let b = (x && 0xffff00000000L) >> 32 in
  let c = (x && 0xffff0000L) >> 16 in
  let d = x && 0xffffL in
  let e = (y && 0xffff000000000000L) >> 48 in
  let f = (y && 0xffff00000000L) >> 32 in
  let g = (y && 0xffff0000L) >> 16 in
  let h = y && 0xffffL in
  sprintf "%Lx:%Lx:%Lx:%Lx:%Lx:%Lx:%Lx:%Lx" a b c d e f g h

let format_timediff x =
  let b = Buffer.create 128 and x = int_of_float x in
  let days = x / 86400 and x = x mod 86400 in
  if days > 0 then bprintf b "%dd" days;
  let hours = x / 3600 and x = x mod 3600 in
  if Buffer.length b > 0 || hours > 0 then bprintf b "%dh" hours;
  let minutes = x / 60 and x = x mod 60 in
  if Buffer.length b > 0 || minutes > 0 then bprintf b "%dm" minutes;
  bprintf b "%ds" x;
  Buffer.contents b

let string_of_peers = function
  | IPv4 (a, b) ->
      sprintf "%s -> %s" (format_ipv4 a) (format_ipv4 b)
  | IPv6 (a, b) ->
      sprintf "%s -> %s" (format_ipv6 a) (format_ipv6 b)

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
             if ihl <> 0 then debug 0 "IHL=%d found" ihl;
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


let flush =
  let last_notice = ref (Unix.gettimeofday ()) in
  fun pcap_handle ht chan signal ->
  let now = Unix.gettimeofday () in
  if now >= !last_notice +. 21600. (* 6 hours *) then begin
    debug 2 "--- %s running since %s (%s ago) ---" Sys.argv.(0) formatted_starting_time (format_timediff (now -. starting_time));
    last_notice := now
  end;
  begin try
    output_ht chan ht;
    flush chan
  with
    | e -> debug 1 "unexpected error while flushing: %s" (Printexc.to_string e)
  end;
  Hashtbl.clear ht;
  if signal = Sys.sigterm then (debug 0 "SIGTERM received, dying"; Pcap.pcap_breakloop pcap_handle) else ()

let is_crans_ipv4 a =
  let x = Int32.logand a 0xfffff800l in (* /21 *)
  x = 0x8ae78800l (* 138.231.136.0/21 *) ||
  x = 0x8ae79000l (* 138.231.144.0/21 *) ||
  a = 0x8ae78706l (* 138.231.135.6, komaz-ext.ens-cachan.fr *)

let is_crans_ipv6 (a1, a2) =
  let x = Int64.logand a1 0xffffffffffff0000L in (* /48 *)
  x = 0x2a010240fe3d0000L (* 2a01:240:fe3d::/48 *) ||
  (a1 = 0x2a010240fe000068L && a2 = 0x2L) (* 2a01:240:fe00:68::2/64, komaz-ext *)

(** Master process: captures packets, flushes a summary to the slave
    process every now and then. *)
let capture pcap_handle chan =
  let ht = Hashtbl.create 1024 in
  let last_ts = ref 0 in
  let sig_handler = Sys.Signal_handle (flush pcap_handle ht chan) in
  let () = Sys.set_signal Sys.sigusr1 sig_handler in
  let () = Sys.set_signal Sys.sigterm sig_handler in
  let r = Pcap.pcap_loop pcap_handle (-1)
    (fun _ hdr data ->
       (* triggers a GC cycle to allow signals to be handled *)
       let () = ignore [Random.int 1000] in
       let data = data, !Clflags.skip_header, (hdr.Pcap.caplen lsl 3) - !Clflags.skip_header in (* dark magic! *)
       try
         let (key, size) =
           (bitmatch data with
              | { ethertype : 16; payload : -1 : bitstring } ->
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
           (flush pcap_handle ht chan Sys.sigusr1; last_ts := ts)
       with
         | Error (Unknown_ethertype 0x806) (* ARP *) -> ()
         | Error e ->
             debug 1 "W: %s" (string_of_error e)
         | Match_failure _ ->
             debug 9 "W: invalid frame (caplen=%d)" hdr.Pcap.caplen;
             Bitstring.hexdump_bitstring stderr data;
             Pervasives.flush stderr
    ) ""
  in debug 4 "pcap_loop exited with code %d" r;
  begin match r with
    | 0 | -2 -> ()
    | -1 -> Pcap.pcap_perror pcap_handle "netacct-crans"
    | x -> debug 1 "W: unknown return value of pcap_loop: %d" x
  end;
  Pcap.pcap_close pcap_handle

(** Slave process: injects summaries from the master process into a
    PostgreSQL database. *)
let rec inject chan =
  let ht = input_ht chan in
  debug 4 "===> Received dump of size %d"  (Hashtbl.length ht);
  let all_values = ref [] in
  (* Top 3 *)
  Hashtbl.iter (fun k v -> all_values := (k, v)::!all_values) ht;
  all_values := List.sort (fun (_, v1) (_, v2) -> v2-v1) !all_values;
  (match !all_values with
     | a::b::c::_ -> all_values := [a; b; c]
     | _ -> ());
  List.iter
    (fun ((peers, _), size) -> debug 9 "%s (%d bytes)" (string_of_peers peers) size)
    !all_values;
  (* Inject into SQL database *)
  begin try
    let pq = new Postgresql.connection ~host:"pgsql.adm.crans.org" ~user:"crans" ~dbname:"filtrage" () in
    let ts = sprintf "TIMESTAMP '%s'" (pq_now ()) in
    let do_insert = ksprintf
      (fun query ->
         let expect = [Postgresql.Command_ok] in
         debug 10 "executing SQL query: %s" query;
         ignore (pq#exec ~expect query))
      (* ugly, but we want lenny compatibility! *)
      "INSERT INTO upload (date, ip_crans, ip_ext, id, port_crans, port_ext, download, upload) VALUES (%s, '%s', '%s', '%d', '%d', '%d', '%d', '%d');"
      ts
    in
    begin
      Hashtbl.iter begin fun k v ->
        try begin match k with
          | (IPv4 (a, b), (proto, sport, dport)) ->
              let (ip_crans, port_crans, ip_ext, port_ext, download, upload) =
                if is_crans_ipv4 a then (a, sport, b, dport, 0, v)
                else if is_crans_ipv4 b then (b, dport, a, sport, v, 0)
                else
                  (debug 2 "Traffic between unknown IP addresses: %s -> %s" (format_ipv4 a) (format_ipv4 b);
                   raise Not_found)
              in
              do_insert
                (format_ipv4 ip_crans) (format_ipv4 ip_ext)
                proto port_crans port_ext download upload
          | (IPv6 (a, b), (proto, sport, dport)) ->
              let (ip_crans, port_crans, ip_ext, port_ext, download, upload) =
                if is_crans_ipv6 a then (a, sport, b, dport, 0, v)
                else if is_crans_ipv6 b then (b, dport, a, sport, v, 0)
                else
                  (debug 2 "Traffic between unknown IP addresses: %s -> %s" (format_ipv6 a) (format_ipv6 b);
                   raise Not_found)
              in
              do_insert
                (format_ipv6 ip_crans) (format_ipv6 ip_ext)
                proto port_crans port_ext download upload
        end with Not_found -> () (* a warning has been issued *)
      end ht;
      pq#finish
    end;
  with Postgresql.Error e ->
    debug 0 "E: PosgreSQL error: %s" (Str.global_replace newline_re " " (Postgresql.string_of_error e))
  end;
  debug 9 "<=== End of dump";
  inject chan

(** Startup logic *)
let () =
  let pcap_handle = Pcap.pcap_open_live !Clflags.interface 128 0 1000 in
  let dl = Pcap.pcap_datalink pcap_handle in
  let dl_name = Pcap.pcap_datalink_val_to_name dl in
  let dl_desc = Pcap.pcap_datalink_val_to_description dl in
  Clflags.skip_header := (* size of header to skip *)
    begin match dl_name with
      | "EN10MB" -> 96
      | "LINUX_SLL" -> 112
      | _ -> ksprintf failwith "unsupported link-type %s (%s)" dl_name dl_desc
    end;
  let inc, outc = Unix.pipe () in
  let inc, outc = Unix.in_channel_of_descr inc, Unix.out_channel_of_descr outc in
  let write_pidfile = match !Clflags.pidfile with
    | Some x ->
        (* we open the pid file prior to going to background, in case of error *)
        let pidfile = open_out x in
        lazy begin
          let pid = Unix.getpid () in
          fprintf pidfile "%d\n%!" pid;
          close_out pidfile;
          pid
        end
    | None ->
        Lazy.lazy_from_fun Unix.getpid
  in
  if !Clflags.daemonize then begin
    (* redirect standard channels *)
    let devnull = Unix.openfile "/dev/null" [Unix.O_RDWR] 0o644 in
    Unix.dup2 devnull Unix.stdout;
    Unix.dup2 devnull Unix.stderr;
    Unix.dup2 devnull Unix.stdin;
    Unix.close devnull;
    (* double-fork magic *)
    if Unix.fork ()  > 0 then exit 0;
    Sys.chdir "/";
    ignore (Unix.setsid ());
    ignore (Unix.umask 0);
    if Unix.fork () > 0 then exit 0;
  end;
  (* but we write the pid after going to background! *)
  let master = Lazy.force write_pidfile in
  match Unix.fork () with
    | 0 ->
        Clflags.process := sprintf "netacct-crans/%s/%d-%d/slave" !Clflags.interface master (Unix.getpid ());
        Pcap.pcap_close pcap_handle;
        close_out outc;
        debug 1 "slave started";
        inject inc
    | slave ->
        Clflags.process := sprintf "netacct-crans/%s/%d-%d/master" !Clflags.interface master slave;
        close_in inc;
        debug 1 "master started -- listening on %s, link-type %s (%s)" !Clflags.interface dl_name dl_desc;
        capture pcap_handle outc
