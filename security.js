//import hmacSHA256 from 'crypto-js/hmac-sha256';
//import csv from 'csv-parser';
//import fs, { write } from 'fs';
var CryptoJS = require("crypto-js");




class Security {
  //#iptomac = new Map(null);// set 16bit to 64 bit
  // #mismatchiptomac = new Map();
  //#revolverposition = new Map();// Positional indicator keyvault
  //#revolverstore = new map();
  #IEEE64tosensorID = new Map();
  #messagecounter = new Map();
  #quarantine = []; // inserted 64Addressstring
  #banneddevices = []; // inserted 64Addressstring
  #alloweddevices = [];

  constructor() {
    this.loadFiles();

  }

  loadFiles() {

    const csv = require('csv-parser');
    const fs = require('fs');

    fs.createReadStream('allowed.csv')
      .pipe(csv())
      .on('data', (row) => {
        //console.log(row);
        var mac = row['ieee64'];
        var sen = row['sensorid'];
        this.#alloweddevices.push(mac);
        this.#IEEE64tosensorID.set(mac, sen);
      })
      .on('end', () => {
        //console.log('CSV file successfully processed');
      });

    fs.createReadStream('banned.csv')
      .pipe(csv())
      .on('data', (row) => {
        //console.log(row);
        var mac = row['ieee64'];
        var sen = row['sensorid'];
        this.#banneddevices.push(mac);
        this.#IEEE64tosensorID.set(mac, sen);
      })
      .on('end', () => {
        //console.log('CSV file successfully processed');
      });

    fs.createReadStream('quarantaine.csv')
      .pipe(csv())
      .on('data', (row) => {
        var mac = row['ieee64'];
        var sen = row['sensorid'];
        this.#quarantine.push(mac);
        this.#IEEE64tosensorID.set(mac, sen);
      })
      .on('end', () => {
        //console.log('CSV file successfully processed');
      });
  }

  writeFiles(file, list) {
    const createCsvWriter = require('csv-writer').createObjectCsvWriter;
    const csvWriter = createCsvWriter({
      path: file + '.csv',
      header: [
        { id: 'sensor', id: 'sensorid' },
        { mac: 'ieee64', mac: 'ieee64' },
      ]
    });

    data = [];

    list.forEach(element => {
      data.push({ sensor: element, mac: lookupSensorID(element) });
    });

    csvWriter
      .writeRecords(data)
      .then(() => console.log('The CSV file was written successfully'));
  }

  printDevices() {
    console.log("items in Allow:");
    console.log(this.#alloweddevices);
    console.log("items in quarantaine:");
    console.log(this.#quarantine);
    console.log("items in banned:");
    console.log(this.#banneddevices);
  }



  checkPacket(topic, message) {
    if (message != null) {
      
      const ieee64 = topic.substr(9);
      //console.log(ieee64)
      try{
      let json = JSON.parse(message);
      console.log(json);
            //check ieee is in network
        //console.log(this.#alloweddevices.includes(ieee64))
        if (this.#alloweddevices.includes(ieee64) != false) {
          //check signature
          try {
            //console.log("SIZE:" + this.#IEEE64tosensorID.size)
            if(this.#IEEE64tosensorID.has(ieee64)){
              const sen = this.#IEEE64tosensorID.get(ieee64);
              const item = json.hash;
              //console.log(item)
              const dataraw = json.data.toString();
              const receivedhash = this.toHexString(item);
              const secret = "VeRy sEcReT "+ sen.toString();
              
              const controllhash = CryptoJS.HmacSHA256(dataraw, secret).toString()

              console.log("Received: " + receivedhash);
              
              if(receivedhash == controllhash){

                                
                if(parseInt(json.messageCount) > this.getMessageCountBySensor(sen)){
                   console.log("received valid packet from " + sen + " with values : " + json.data);
                   this.setMessageCountBySensor(sen,json.messageCount);
                }
                else{
                   console.log("DUPLICATE MESSAGE from " + sen + " with values : " + json.data);
                   this.setMessageCountBySensor(sen,json.messageCount);
                }
                            



                console.log("DEBUG: this is sensor " + sen)
                
              }
              else{
                console.log("DEBUG: Hash does not match")
              }
            }
            else{
              console.log("this has no binding in MAC to SENSOR");
            }
            
            //check 
            try {

            }
            catch (err) {
              console.log("4" + err)
            }
          }
          catch (err) {
            console.log("2" + err)
          }
        }
        else {
          console.debug("WARNING:" + ieee64 + "is not ADDED to the network");
        }
      }
      catch (err) {
        console.log("1" + err)
      }
      finally {

      }
    }
    else {
      console.debug(message);
    }
  }


  getMessageCountBySensor(SensorID){
    try{
    if(this.#messagecounter.has(SensorID.toString)){
       return this.#messagecounter.get(SensorID.toString);
    }
    else {
      return 1;
    }
  }
  catch(err){
    console.log("error occured: " + err);
  }
    
  }


  setMessageCountBySensor(SensorID,val){
    this.#messagecounter.set(SensorID.toString,val);
  }

  joinDevice(IEE64Address, SensorID) {
    // generate hashlist.
    this.#alloweddevices.push(IEE64Address);
    this.#quarantine = this.removalFromList(this.#quarantine, IEE64Address);
    this.#banneddevices = this.removalFromList(this.#banneddevices, IEE64Address);
    this.#IEEE64tosensorID.push(IEE64Address, SensorID);
    //generateSecretKey(SensorID);

  }


  quarantaineDevice(IEE64Address) {
    this.#alloweddevices = this.removalFromList(this.#alloweddevices, IEE64Address);
    this.#quarantine.push(IEE64Address);
    this.#banneddevices = this.removalFromList(this.#banneddevices, IEE64Address);
  }


  banDevice(IEE64Address) {
    this.#alloweddevices = this.removalFromList(this.#alloweddevices, IEE64Address);
    this.#quarantine = this.removalFromList(this.#quarantine, IEE64Address);
    this.#banneddevices.push(IEE64Address);
  }

  removalFromList(array, item) { return array.filter(function (ele) { return ele == item; }); }


  getAllowedDevices() {
    return this.#alloweddevices
  }

  lookupSensorID(ieee64) {
    return this.#IEEE64tosensorID.get(ieee64);
  }




toHexString(byteArray) {
  return Array.prototype.map.call(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}
toByteArray(hexString) {
  var result = [];
  for (var i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}



}// class

module.exports = Security



