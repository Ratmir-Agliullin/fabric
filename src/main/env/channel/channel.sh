export PATH=${PWD}/../bin:${PWD}:$PATH
export FABRIC_CFG_PATH=${PWD}
configtxgen -profile TwoOrgsOrdererGenesis -outputBlock genesis.block
configtxgen -profile TwoOrgsChannel -outputCreateChannelTx channel.tx -channelID mychannel