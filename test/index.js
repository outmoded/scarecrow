// Load modules

var Code = require('code');
var Hapi = require('hapi');
var Lab = require('lab');
var Oz = require('oz');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;


describe('Scarecrow', function () {

    it('performs a full authorization flow', function (done) {

        var encryptionPassword = 'password';

        var apps = {
            social: {
                id: 'social',
                scope: ['a', 'b', 'c'],
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            },
            network: {
                id: 'network',
                scope: ['b', 'x'],
                key: 'witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi',
                algorithm: 'sha256'
            }
        };

        var grant = {
            id: 'a1b2c3d4e5f6g7h8i9j0',
            app: 'social',
            user: 'john',
            exp: Oz.hawk.utils.now() + 60000
        };

        var options = {
            oz: {
                encryptionPassword: encryptionPassword,

                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },

                loadGrantFunc: function (id, callback) {

                    var ext = {
                        public: 'everybody knows',
                        private: 'the the dice are loaded'
                    };

                    callback(null, grant, ext);
                }
            }
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            // Add strategy

            server.auth.strategy('oz', 'oz', true, options);

            // Add a protected resource

            server.route({
              path: '/protected',
              method: 'GET',
              config: {
                auth: {
                  entity: 'user'
                },
                handler: function (request, reply) {
                  reply(request.auth.credentials.user + ' your in!');
                }
              }
            });

            // The app requests an app ticket using Hawk authentication

            var req = {
                method: 'POST',
                url: 'http://example.com/oz/app',
                headers: {
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            server.inject(req, function (res) {

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                var appTicket = res.result;

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp
                    // The app exchanges the rsvp for a ticket

                    var req = {
                        method: 'POST',
                        url: 'http://example.com/oz/rsvp',
                        headers: {
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                        },
                        payload: JSON.stringify({ rsvp: rsvp })
                    };

                    server.inject(req, function (res) {

                        var userTicket = res.result;

                        // The app reissues the ticket

                        var req = {
                            method: 'POST',
                            url: 'http://example.com/oz/reissue',
                            headers: {
                                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', userTicket).field
                            }
                        };

                        server.inject(req, function (res) {

                            var newTicket = res.result;

                            var req = {
                                method: 'GET',
                                url: 'http://example.com/protected',
                                headers: {
                                    authorization: Oz.client.header('http://example.com/protected', 'GET', newTicket).field
                                }
                            };

                            server.inject(req, function (res) {

                                expect(res.payload).to.equal('john your in!');
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    it('fails to authenticate a request with mismatching app id', function (done) {

        var encryptionPassword = 'password';

        var app = {
            id: 'social',
            scope: ['a', 'b', 'c'],
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256'
        };

        var grant = {
            id: 'a1b2c3d4e5f6g7h8i9j0',
            app: 'social',
            user: 'john',
            exp: Oz.hawk.utils.now() + 60000
        };

        var options = {
            oz: {
                encryptionPassword: encryptionPassword,

                loadAppFunc: function (id, callback) {

                    callback(null, app);
                },

                loadGrantFunc: function (id, callback) {

                    callback(null, grant);
                }
            }
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            // Add strategy

            server.auth.strategy('oz', 'oz', true, options);

            // Add a protected resource

            server.route({
              path: '/protected',
              method: 'GET',
              config: {
                auth: {
                  entity: 'user'
                },
                handler: function (request, reply) {
                  reply(request.auth.credentials.user + ' your in!');
                }
              }
            });

            // The app requests an app ticket using Hawk authentication

            var req = {
                method: 'POST',
                url: 'http://example.com/oz/app',
                headers: {
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', app).field
                }
            };

            server.inject(req, function (res) {

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                var appTicket = res.result;

                Oz.ticket.rsvp(app, grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp
                    // The app exchanges the rsvp for a ticket

                    var req = {
                        method: 'POST',
                        url: 'http://example.com/oz/rsvp',
                        headers: {
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                        },
                        payload: JSON.stringify({ rsvp: rsvp })
                    };

                    server.inject(req, function (res) {

                        var userTicket = res.result;
                        userTicket.app = '567';

                        var req = {
                            method: 'GET',
                            url: 'http://example.com/protected',
                            headers: {
                                authorization: Oz.client.header('http://example.com/protected', 'GET', userTicket).field
                            }
                        };

                        server.inject(req, function (res) {

                            expect(res.statusCode).to.equal(401);
                            expect(res.result.message).to.equal('Error: Mismatching application id');
                            done();
                        });
                    });
                });
            });
        });
    });
});
