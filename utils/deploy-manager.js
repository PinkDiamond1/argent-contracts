require('dotenv').config();
const etherlime = require('etherlime-lib');
const { Wallet } = require('ethers')
const path = require("path");

const Configurator = require('./configurator.js');
const ConfiguratorLoader = require('./configurator-loader.js');
const PrivateKeyLoader = require('./private-key-loader.js');
const ABIUploader = require('./abi-uploader.js');
const VersionUploader = require('./version-uploader.js');

const defaultConfigs = {
    gasPrice: 20000000000, // 20 Gwei
    gasLimit: 6000000
}

class DeployManager {
    constructor(network) {
        this.network = network;

        this.remotelyManagedNetworks = (process.env.S3_BUCKET_SUFFIXES || "").split(':');

        // config
        let configLoader;
        if (this.remotelyManagedNetworks.includes(this.network)) {
            const bucket = `${process.env.S3_BUCKET_PREFIX}-${this.network}`;
            const key = process.env.S3_CONFIG_KEY;
            configLoader = new ConfiguratorLoader.S3(bucket, key);
        } else {
            const filePath = path.join(__dirname, './config', `${this.network}.json`)
            configLoader = new ConfiguratorLoader.Local(filePath)
        }
        this.configurator = new Configurator(configLoader);
    }

    async setup() {
        await this.configurator.load();
        const config = this.configurator.config;

        // getting private key if any is available
        let pkey = undefined;
        if (config.settings.privateKey && config.settings.privateKey.type === 'plain') {
            const { value, envvar } = config.settings.privateKey.options;
            pkey = value || process.env[envvar];
        } else if (config.settings.privateKey && config.settings.privateKey.type === 's3') {
            const options = config.settings.privateKey.options;
            const pkeyLoader = new PrivateKeyLoader(options.bucket, options.key);
            pkey = await pkeyLoader.fetch();
        }

        // setting deployer
        if (config.settings.deployer.type === 'ganache') {
            this.deployer = new etherlime.EtherlimeGanacheDeployer(pkey); // will use etherlime accounts if pkey is undefined
        } else if (config.settings.deployer.type === 'infura') {
            const { network, key, envvar } = config.settings.deployer.options;
            this.deployer = new etherlime.InfuraPrivateKeyDeployer(pkey, network, key || process.env[envvar], defaultConfigs);
        } else if (config.settings.deployer.type === 'jsonrpc') {
            const { url } = config.settings.deployer.options;
            this.deployer = new etherlime.JSONRPCPrivateKeyDeployer(pkey, url, defaultConfigs);
        }

        // setting backend accounts and multi-sig owner for test environments not managed on S3
        if (!this.remotelyManagedNetworks.includes(this.network)) {
            const account = await this.deployer.signer.getAddress();
            this.configurator.updateBackendAccounts([account]);
            this.configurator.updateMultisigOwner([account]);
        }

        // abi upload
        if (config.settings.abiUpload) {
            this.abiUploader = new ABIUploader.S3(config.settings.abiUpload.bucket);
        } else {
            this.abiUploader = new ABIUploader.None();
        }

        // version upload
        if (config.settings.versionUpload) {
            this.versionUploader = new VersionUploader.S3(config.settings.versionUpload.bucket, config.settings.versionUpload.url);
        } else {
            const dirPath = path.join(__dirname, './versions/', this.network);
            this.versionUploader = new VersionUploader.Local(dirPath);
        }
    }
}

module.exports = DeployManager;
