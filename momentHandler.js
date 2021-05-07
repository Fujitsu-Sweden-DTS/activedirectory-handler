"use strict";
const moment = require("moment");

exports.formatDatestring = function (dateString, inputFormat, returnFormat) {
  if (inputFormat === null) {
    return moment(dateString).format(returnFormat);
  }
  return moment(dateString, inputFormat).format(returnFormat);
};
