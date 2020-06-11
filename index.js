//import hmacSHA256 from 'crypto-js/hmac-sha256';

const mqtt = require('mqtt')
var client = mqtt.connect('mqtt://192.168.1.217:1883')
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

