
import {certificateFromString, certificateToString} from "../certificate";

describe('Typescript usage suite', () => {

    it('should serialize and deserialize certificate correctly', async function () {
        let cert = `11
1111
5566Dn4ZXXbBK5LJdUsE7L3pG9qdAzdPY47adjzkhEx9
3HNXpW2cLdqXzf4jz5EhsGEBFkWzuVdBCyxzJUZu2WPVU7kpzPjatcqvdJMjTtcycVAdaV5qh2fCGphSmw8UMBkr
158981172690500
1589974723504
2EvoZAZaGjKWFVdr36F1jphQ5cW7eK3yM16mqEHwQyr7
4UAJQWzB3nTchBtwARHAhsn7wjdYtqUHojps9xV6JkuLENV8KRiWM3BhQByx5KijumkaNjr7MhHjouLawmiN1A4d
1590061123504
1589974723504`;

        let deser = await certificateFromString(cert);
        let ser = certificateToString(deser);

        expect(ser).toEqual(cert);
    });
})

// TODO implement this test when `trust-graph-js - fluence-js - fluence node` chain will be available
// export async function testCerts() {
//     const key1 = await generatePeerId();
//     const key2 = await generatePeerId();
//
//     // connect to two different nodes
//     const cl1 = new FluenceClientImpl(key1);
//     const cl2 = new FluenceClientImpl(key2);
//
//     await cl1.connect('/dns4/134.209.186.43/tcp/9003/ws/p2p/12D3KooWBUJifCTgaxAUrcM9JysqCcS4CS8tiYH5hExbdWCAoNwb');
//     await cl2.connect('/ip4/134.209.186.43/tcp/9002/ws/p2p/12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er');
//
//     let trustGraph1 = new TrustGraph(/* cl1 */);
//     let trustGraph2 = new TrustGraph(/* cl2 */);
//
//     let issuedAt = new Date();
//     let expiresAt = new Date();
//     // certificate expires after one day
//     expiresAt.setDate(new Date().getDate() + 1);
//
//     // create root certificate for key1 and extend it with key2
//     let rootCert = await nodeRootCert(key1);
//     let extended = await issue(key1, key2, rootCert, expiresAt.getTime(), issuedAt.getTime());
//
//     // publish certificates to Fluence network
//     await trustGraph1.publishCertificates(key2.toB58String(), [extended]);
//
//     // get certificates from network
//     let certs = await trustGraph2.getCertificates(key2.toB58String());
//
//     // root certificate could be different because nodes save trusts with bigger `expiresAt` date and less `issuedAt` date
//     expect(certs[0].chain[1].issuedFor.toB58String()).to.be.equal(extended.chain[1].issuedFor.toB58String());
//     expect(certs[0].chain[1].signature).to.be.equal(extended.chain[1].signature);
//     expect(certs[0].chain[1].expiresAt).to.be.equal(extended.chain[1].expiresAt);
//     expect(certs[0].chain[1].issuedAt).to.be.equal(extended.chain[1].issuedAt);
//
//     await cl1.disconnect();
//     await cl2.disconnect();
// }
