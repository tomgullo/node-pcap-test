var moment = require("moment");

var fs = require("fs");
var log = fs.createWriteStream('log3.txt', {'flags': 'a'});

var redis = require("redis"), client = redis.createClient();
client.on("error", function (err) { console.log("Error " + err); });

var pcap = require("pcap"),
    pcap_session = pcap.createSession("", 
            "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"),
    matcher_get = /GET|POST/i,
    referer_match = /^Referer/
    matcher_text_html = /Accept: text\/html/;

console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
            data = packet.link.ip.tcp.data;

        if ( data && matcher_get.test(data.toString()) )   {
        log.write(data + "\nbreak\n"); 
        //if ( data && matcher_get.test(data.toString()) && matcher_text_html.test(data.toString())  ) {
        
            var http = get_data_from_packet(data, packet.link.ip, packet.pcap_header.time_ms);

            if (http.ok === "true") {
                client.incr("nextid_id", function(err, res) {
                    console.log(res);
                    var newid = "http:"+res;
                    
                    client.hmset([newid, 
                        "url", http.url, 
                        "host", http.host, 
                        "agent", http.agent,
                        "lang", http.lang, 
                        "saddr", http.saddr, 
                        "daddr", http.daddr,
                        "time", http.time, 
                        "time_format", http.time_format,
                        "data", data]);

                    client.zadd("http_list", http.time, newid+http.host);
                    client.sadd("hosts", http.host);
                    client.sadd("ips", http.daddr);
                    client.sadd("urls", http.url);
                    client.zincrby("request_count", 1, http.host);
                    client.sadd(http.host, http.url);
                });
            }


        }
});

function get_data_from_packet(data, ip, time_ms) {
    var http = {};

    try {
        var d = data.toString().split("\n");
        var ref = "";
        for (e in d) {
            if ( /^Referer/.test(d[e]) ) { 
                http.ref = d[e].replace("Referer:", ""); 
            }
            if ( /^Host/.test(d[e]) ) { 
                var temp_host = d[1].split(" ")[1]
                if (temp_host) {
                    http.host = temp_host.replace("\r", "");
                }
            }
            if ( /^Agent/.test(d[e]) ) { 
                http.agent = d[e].replace("Agent:", "");
            }
            if ( /^Accept-Language/.test(d[e]) ) { 
                http.lang = d[e].replace("Accept-Language", "");
            }
        }
        http.url = d[0].split(" ")[1];

        http.saddr = ip.saddr; 
        http.daddr = ip.daddr;

        http.time = time_ms; 
        http.time_format = moment(http.time).format("MM/DD/YY h:mm");
    } catch(ex) {
        console.log("exception " + ex);

    }

    http.ok = "true";
    return http;
}


