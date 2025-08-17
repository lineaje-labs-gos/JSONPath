import vm from 'vm';
import {JSONPath} from './jsonpath.js';
import {SafeScript} from './jsonpath-browser.js';

JSONPath.prototype.vm = vm;
JSONPath.prototype.safeVm = {Script: SafeScript};

export {
    JSONPath,
    SafeScript
};
