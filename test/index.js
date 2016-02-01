'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');
const Oz = require('oz');
const Scarecrow = require('../');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


describe('Scarecrow', () => {

    it('performs a full authorization flow', (done) => {

        const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

        const apps = {
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

        const grant = {
            id: 'a1b2c3d4e5f6g7h8i9j0',
            app: 'social',
            user: 'john',
            exp: Oz.hawk.utils.now() + 60000
        };

        const options = {
            oz: {
                encryptionPassword: encryptionPassword,

                loadAppFunc: function (id, callback) {

                    callback(null, apps[id]);
                },

                loadGrantFunc: function (id, callback) {

                    const ext = {
                        public: 'everybody knows',
                        private: 'the the dice are loaded'
                    };

                    callback(null, grant, ext);
                }
            }
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(Scarecrow, (err) => {

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

            let req = {
                method: 'POST',
                url: 'http://example.com/oz/app',
                headers: {
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).field
                }
            };

            server.inject(req, (res1) => {

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                const appTicket = res1.result;

                Oz.ticket.rsvp(apps.social, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp
                    // The app exchanges the rsvp for a ticket

                    req = {
                        method: 'POST',
                        url: 'http://example.com/oz/rsvp',
                        headers: {
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                        },
                        payload: JSON.stringify({ rsvp: rsvp })
                    };

                    server.inject(req, (res2) => {

                        const userTicket = res2.result;

                        // The app reissues the ticket

                        req = {
                            method: 'POST',
                            url: 'http://example.com/oz/reissue',
                            headers: {
                                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', userTicket).field
                            }
                        };

                        server.inject(req, (res3) => {

                            const newTicket = res3.result;

                            req = {
                                method: 'GET',
                                url: 'http://example.com/protected',
                                headers: {
                                    authorization: Oz.client.header('http://example.com/protected', 'GET', newTicket).field
                                }
                            };

                            server.inject(req, (res4) => {

                                expect(res4.payload).to.equal('john your in!');
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    it('fails to authenticate a request with mismatching app id', (done) => {

        const encryptionPassword = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

        const app = {
            id: 'social',
            scope: ['a', 'b', 'c'],
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256'
        };

        const grant = {
            id: 'a1b2c3d4e5f6g7h8i9j0',
            app: 'social',
            user: 'john',
            exp: Oz.hawk.utils.now() + 60000
        };

        const options = {
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

        const server = new Hapi.Server();
        server.connection();

        server.register(Scarecrow, (err) => {

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

            let req = {
                method: 'POST',
                url: 'http://example.com/oz/app',
                headers: {
                    authorization: Oz.client.header('http://example.com/oz/app', 'POST', app).field
                }
            };

            server.inject(req, (res1) => {

                // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

                const appTicket = res1.result;

                Oz.ticket.rsvp(app, grant, encryptionPassword, {}, (err, rsvp) => {

                    expect(err).to.not.exist();

                    // After granting app access, the user returns to the app with the rsvp
                    // The app exchanges the rsvp for a ticket

                    req = {
                        method: 'POST',
                        url: 'http://example.com/oz/rsvp',
                        headers: {
                            authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).field
                        },
                        payload: JSON.stringify({ rsvp: rsvp })
                    };

                    server.inject(req, (res2) => {

                        const userTicket = res2.result;
                        userTicket.app = '567';

                        req = {
                            method: 'GET',
                            url: 'http://example.com/protected',
                            headers: {
                                authorization: Oz.client.header('http://example.com/protected', 'GET', userTicket).field
                            }
                        };

                        server.inject(req, (res3) => {

                            expect(res3.statusCode).to.equal(401);
                            expect(res3.result.message).to.equal('Mismatching application id');
                            done();
                        });
                    });
                });
            });
        });
    });
});
