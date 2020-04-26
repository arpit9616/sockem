/* 
 * (C) 2015 - 2018 TekMonks. All rights reserved.
 */

function getDateTime() {
    const date = new Date();

    let hour = date.getHours(); hour = (hour < 10 ? "0" : "") + hour;
    let min = date.getMinutes(); min = (min < 10 ? "0" : "") + min;
    let sec = date.getSeconds(); sec = (sec < 10 ? "0" : "") + sec;
    let year = date.getFullYear();
    let month = date.getMonth() + 1; month = (month < 10 ? "0" : "") + month;
    let day = date.getDate(); day = (day < 10 ? "0" : "") + day;

    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;
}

function getIPAsBytes(ip) {
    const isIPv6 = ip.indexOf(".") != -1 ? false:true;
    const bytes = Buffer.alloc(isIPv6?16:4);
    const splits = (isIPv6?expandIPv6Address(ip):ip).split(isIPv6?":":".");
    for (let i = 0; i < splits.length; i++) (isIPv6?bytes.writeInt16BE:bytes.writeInt8).call(bytes, parseInt(splits[i]), isIPv6?i*2:i);

    return bytes;
}

function getIPFromBytes(bytes) {
    if (bytes.length == 4) return bytes.join(".");  // IPv4
    
    const retIP = "";
    for (let i = 0; i < 16; i+2) {
        const int16 = bytes.slice(i, i+2).readInt16BE();
        retIp += int16 + i == 14? "" : ":";
    }

    return retIP;
}

function expandIPv6Address(address) // from: https://gist.github.com/Mottie/7018157
{
    let fullAddress = "", expandedAddress = "", validGroupCount = 8, validGroupSize = 4, ipv4 = "";
    const extractIpv4 = /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/, validateIpv4 = /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})/;

    // look for embedded ipv4
    if (validateIpv4.test(address)) {
        const groups = address.match(extractIpv4);
        for(let i=1; i<groups.length; i++) ipv4 += ("00" + (parseInt(groups[i], 10).toString(16)) ).slice(-2) + ( i==2 ? ":" : "" );
        address = address.replace(extractIpv4, ipv4);
    }

    if (address.indexOf("::") == -1) fullAddress = address; // All eight groups are present.
    else {  // Consecutive groups of zeroes have been collapsed with "::".
        const sides = address.split("::"); let groupsPresent = 0;
        for (let i=0; i<sides.length; i++) groupsPresent += sides[i].split(":").length;
        fullAddress += sides[0] + ":";
        for (let i=0; i<validGroupCount-groupsPresent; i++) fullAddress += "0000:";
        fullAddress += sides[1];
    }
    const groups = fullAddress.split(":");
    for (let i=0; i<validGroupCount; i++) {
        while(groups[i].length < validGroupSize) groups[i] = "0" + groups[i];
        expandedAddress += (i!=validGroupCount-1) ? groups[i] + ":" : groups[i];
    }
    return expandedAddress;
}

module.exports = { getDateTime, getIPAsBytes, getIPFromBytes, expandIPv6Address };