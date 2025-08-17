import {checkBuiltInVMAndNodeVM} from '../test-helpers/checkVM.js';

checkBuiltInVMAndNodeVM(function (vmType, setBuiltInState) {
    describe(`JSONPath - Potentially malicious path expression tests (${vmType})`, function () {
        before(setBuiltInState);

        const json = {
            "name": "root",
            "children": [
                {"name": "child1", "children": [{"name": "child1_1"}, {"name": "child1_2"}]},
                {"name": "child2", "children": [{"name": "child2_1"}]},
                {"name": "child3", "children": [{"name": "child3_1"}, {"name": "child3_2"}]}
            ]
        };

        const pathDoS = "$[?(con = constructor; dp = con.defineProperty; gopd = con.getOwnPropertyDescriptor; f = gopd(con, 'entries').value; alt = gopd(con.getPrototypeOf(f), 'apply'); dp(con.getPrototypeOf(_$_root.body), 'toString', alt);)]";

        it('should throw when using "process" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$[?(@.foo === process)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "constructor" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$..[?(constructor)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "eval(" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$[?(@.data === eval(123))]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "Function" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$[?(@.test === Function)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "vm.runInNewContext" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$..[?(@.key === vm.runInNewContext)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "spawn" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$[?(@.action === spawn)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "bind" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$..[?(@.something === bind)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "apply" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$[?(@.testVal === apply)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using "execSync" literal in path', () => {
            expect(() => {
                jsonpath({
                    json,
                    path: '$..[?(@.cmdExec === execSync)]'
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });

        it('should throw when using a complete DoS/SSRF script', () => {
            expect(() => {
                jsonpath({
                    json: {
                        referrer: {
                            value: "http://authorized.com",
                            writable: true
                        },
                        method: {
                            value: "POST",
                            writable: true
                        },
                        body: {
                            value: "Hello, World!",
                            writable: true
                        }
                    },
                    path: pathDoS
                });
            }).to.throw(Error, /Unsafe expression rejected by JSONPath/u);
        });
    });
});
