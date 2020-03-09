var curves = require('./curves.json')
module.exports = CurveInfo;

function CurveInfo(name){
    var info = curves[name];
    function isSupportedFormat(format){
        for (const support_format of info.support_formats)
        {
            if (support_format === format)
                return true;
        }
        return false;
    }
    return {
        info,
        isSupportedFormat
    }
}

CurveInfo.getInfoByName = function(name){
    return CurveInfo(name);
}

CurveInfo.getInfoByType = function(type){
    const keys = Object.keys(curves);
    for (const key of keys)
    {
        const curve = curves[key]
        if (curve.keyType === type)
            return CurveInfo(curve.name);
    }
    return null;
}
