var redis = require("redis"), client = redis.createClient();

client.on("error", function (err) { console.log("Error " + err); });

/*
client.set("string key", "string val", redis.print);
client.hset("hash key", "hashtest 1", "some value", redis.print);
client.hset(["hash key", "hashtest 2", "some other value"], redis.print);
client.hkeys("hash key", function (err, replies) {
        console.log(replies.length + " replies:");
            replies.forEach(function (reply, i) {
                        console.log("    " + i + ": " + reply);
                            });
                client.quit();
});
*/

/*
client.incr("nextid", function(err, res) {
    client.zadd("list", res, res);
});
client.zadd("list2", 22, "twenty two");
client.zadd("list2", 23, "twenty three");
*/
client.zrevrange("list2", 0, -1, 'WITHSCORES', function(err, res) {
    console.log(res);
    client.quit();
});


    
