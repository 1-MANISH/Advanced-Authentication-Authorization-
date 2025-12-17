import QRCode from 'qrcode'

const otpAuthUrl = process.argv[2] as string

if(!otpAuthUrl){
        throw new Error('Pass otp auth url as first argument')
}

async function main(){

        await QRCode.toFile('totp.png',otpAuthUrl,{scale: 10})

        console.log('QR code saved to totp.png')
}


main() .catch(err=>{
        console.log(err)
        process.exit(1)
})

