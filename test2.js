//var redis = require("redis"), client = redis.createClient();
var moment = require("moment");

//client.on("error", function (err) { console.log("Error " + err); });

var pcap = require("pcap"),
    pcap_session = pcap.createSession("", 
            "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"),
    fs = require("fs"),
    matcher_get = /GET|POST/i,
    referer_match = /^Referer/
    matcher_text_html = /Accept: text\/html/;

var log = fs.createWriteStream('log2.txt', {'flags': 'a'});
console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
            data = packet.link.ip.tcp.data;

        if ( data && matcher_get.test(data.toString()) && matcher_text_html.test(data.toString())  ) {
            var http = {};

            var d = data.toString().split("\n");
            var ref = ""
            for (e in d) {
                if ( /^Referer/.test(d[e]) ) { http.ref = d[e].replace("Referer:", ""); }
            }
            http.url = d[0].split(" ")[1];
            http.host = d[1].split(" ")[1];
            http.agent = d[2].replace("Agent:", "");
            http.lang = d[4].replace("Accept-Language:", "");

            ip = packet.link.ip;
            http.saddr = ip.saddr; 
            http.daddr = ip.daddr;

            http.time = packet.pcap_header.time_ms;
            http.time_format = moment(http.time).format("MM/DD/YY h:mm");

            //log.write("\n\n" + client.incr("nextid") + "\n\n");
        

            //client.hset("hash key", "hashtest 1", "some value", redis.print);

            log.write(JSON.stringify(http));
        }
});
