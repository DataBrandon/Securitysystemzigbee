const mqtt = require('mqtt')
var client = mqtt.connect('mqtt://178.128.251.170:1883');
client.options.username = "Debug";
client.options.password = "wijwilleninloggen";
var Security = require('./security');


var sec = new Security();
//sec.printDevices();



client.on('connect',function(){
    const all = sec.getAllowedDevices();
    all.forEach(element => {
        client.subscribe('/sensors/' + element,function (err){
            if(!err){
                console.log('subscribed to sensors/' + element);
                
            }
        })
    });
    
});

client.on('message',function(topic,message){
    
    //console.log(message.toString())
    sec.checkPacket(topic,message);
})

