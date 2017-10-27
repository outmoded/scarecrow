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

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Scarecrow', () => {

    it('performs a full authorization flow', async () => {

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
                encryptionPassword,

                loadAppFunc: (id) => apps[id],
                loadGrantFunc: function (id) {

                    const ext = {
                        public: 'everybody knows',
                        private: 'the the dice are loaded'
                    };

                    return { grant, ext };
                }
            }
        };

        const server = Hapi.server();
        await server.register(Scarecrow);

        // Add strategy

        server.auth.strategy('oz', 'oz', options);
        server.auth.default('oz');

        // Add a protected resource

        server.route({
            path: '/protected',
            method: 'GET',
            config: {
                auth: {
                    entity: 'user'
                },
                handler: function (request) {

                    return request.auth.credentials.user + ' your in!';
                }
            }
        });

        // The app requests an app ticket using Hawk authentication

        let req = {
            method: 'POST',
            url: 'http://example.com/oz/app',
            headers: {
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', apps.social).header
            }
        };

        const res1 = await server.inject(req);
        expect(res1.statusCode).to.equal(200);

        // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

        const appTicket = res1.result;
        const rsvp = await Oz.ticket.rsvp(apps.social, grant, encryptionPassword);

        // After granting app access, the user returns to the app with the rsvp
        // The app exchanges the rsvp for a ticket

        req = {
            method: 'POST',
            url: 'http://example.com/oz/rsvp',
            headers: {
                authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
            },
            payload: JSON.stringify({ rsvp })
        };

        const res2 = await server.inject(req);
        const userTicket = res2.result;

        // The app reissues the ticket

        req = {
            method: 'POST',
            url: 'http://example.com/oz/reissue',
            headers: {
                authorization: Oz.client.header('http://example.com/oz/reissue', 'POST', userTicket).header
            }
        };

        const res3 = await server.inject(req);
        const newTicket = res3.result;

        req = {
            method: 'GET',
            url: 'http://example.com/protected',
            headers: {
                authorization: Oz.client.header('http://example.com/protected', 'GET', newTicket).header
            }
        };

        const res4 = await server.inject(req);
        expect(res4.payload).to.equal('john your in!');
    });

    it('fails to authenticate a request with mismatching app id', async () => {

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
                encryptionPassword,
                loadAppFunc: () => app,
                loadGrantFunc: () => ({ grant })
            }
        };

        const server = Hapi.server();
        await server.register(Scarecrow);

        // Add strategy

        server.auth.strategy('oz', 'oz', options);
        server.auth.default('oz');

        // Add a protected resource

        server.route({
            path: '/protected',
            method: 'GET',
            config: {
                auth: {
                    entity: 'user'
                },
                handler: function (request) {

                    return request.auth.credentials.user + ' your in!';
                }
            }
        });

        // The app requests an app ticket using Hawk authentication

        let req = {
            method: 'POST',
            url: 'http://example.com/oz/app',
            headers: {
                authorization: Oz.client.header('http://example.com/oz/app', 'POST', app).header
            }
        };

        const res1 = await server.inject(req);

        // The user is redirected to the server, logs in, and grant app access, resulting in an rsvp

        const appTicket = res1.result;

        const rsvp = await Oz.ticket.rsvp(app, grant, encryptionPassword);

        // After granting app access, the user returns to the app with the rsvp
        // The app exchanges the rsvp for a ticket

        req = {
            method: 'POST',
            url: 'http://example.com/oz/rsvp',
            headers: {
                authorization: Oz.client.header('http://example.com/oz/rsvp', 'POST', appTicket).header
            },
            payload: JSON.stringify({ rsvp })
        };

        const res2 = await server.inject(req);
        const userTicket = res2.result;
        userTicket.app = '567';

        req = {
            method: 'GET',
            url: 'http://example.com/protected',
            headers: {
                authorization: Oz.client.header('http://example.com/protected', 'GET', userTicket).header
            }
        };

        const res3 = await server.inject(req);
        expect(res3.statusCode).to.equal(401);
        expect(res3.result.message).to.equal('Mismatching application id');
    });
});
