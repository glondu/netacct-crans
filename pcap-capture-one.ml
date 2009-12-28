(** Capture one packet using libpcap *)

open Printf

let capture pcap_handle =
  let r = Pcap.pcap_loop pcap_handle 1
    (fun _ hdr pkt ->
       let n = hdr.Pcap.caplen in
       let data = String.create n in
       let () = String.unsafe_blit pkt 0 data 0 n in
       print_string data;
       flush stdout) ""
  in eprintf "pcap_loop exited with code %d\n%!" r;
  begin match r with
    | 0 | -2 -> ()
    | -1 -> Pcap.pcap_perror pcap_handle "pcap-capture-one"
    | x -> eprintf "W: unknown return value of pcap_loop: %d\n%!" x
  end;
  Pcap.pcap_close pcap_handle

let () =
  let pcap_handle = Pcap.pcap_open_live Sys.argv.(1) 2000 0 1000 in
  capture pcap_handle
