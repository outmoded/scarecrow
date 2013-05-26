// Load modules

var Lab = require('lab');
var Hapi = require('hapi');
var Oz = require('oz');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


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
        server.pack.require('../', options, function (err) {

            expect(err).to.not.exist;

            // Add a protected resource

            server.route({ path: '/protected', method: 'GET', config: { auth: 'oz', handler: function () { this.reply('your in!'); } } });

            // The app requests an app ticket using Hawk authentication

            var req = {
                method: 'POST',
                url: 'http://example.com/oz/app',
                headers: {
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps['social']).field
                }
            };

            server.inject(req, function (res) {

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                var appTicket = res.result;

                Oz.ticket.rsvp(apps['social'], grant, encryptionPassword, {}, function (err, rsvp) {

                    expect(err).to.not.exist;

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

                                expect(res.payload).to.equal('your in!');
                                done();
                            });
                        });
                    });
                });
            });
        });
    });
});


