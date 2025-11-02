module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",     // Localhost
      port: 8545,            // Change this from 7545 to 8545
      network_id: "*",       // Match any network id
    },
  },
  
  compilers: {
    solc: {
      version: "0.5.16",
    }
  },
};
