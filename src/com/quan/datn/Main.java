package com.quan.datn;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;


public class Main extends Applet
{
	
	// INS Luu va xuat thong tin benh nhan
	final static byte INS_INSERT_INFO = (byte)0x00;
	final static byte INS_READ_INFO = (byte)0x01;
	
	// INT Thanh Toan
	final static byte INS_CREDIT = (byte) 0x02;
	final static byte INS_DEBIT = (byte) 0x03;
	final static byte INS_GET_BALANCE = (byte) 0x04;
	
	
	// INS Xac nhan ma pin
	final static byte INS_VERYFY = (byte)0x05;
	// INS Unblock khi nhap sai ma pin nhieu lan
	final static byte INS_UNBLOCK_CARD = (byte)0x06;
	// INS Thay doi ma pin
	final static byte INS_CHANGE_PIN = (byte)0x07;
	
	// INS Tao chu ky xac thuc
	final static byte INS_SIGN = (byte)0x08;
	// INS doc khoa public key
	final static byte INS_READ_PUBLICKEY_EXP = (byte) 0x09;
	final static byte INS_READ_PUBLICKEY_MOD = (byte) 0x10;
	
	// So lan nhap ma pin sai truoc khi khoa the
	final static byte PIN_TRY_LIMIT =(byte)0x03;
	// maximum size PIN
	final static byte MAX_PIN_SIZE =(byte)0x08;
	
	// SW phan hoi khi nhap ma pin
	final static short SW_VERIFICATION_FAILED = 0x6312;
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6311;
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
   
	// Exception Thong bao so tien thanh toan lon hon so tien con trong the
	final static short SW_NEGATIVE_BALANCE = 0x6A85;
	
	private static byte[] temp, infomation;
	private static byte[] pinCard;
	private static byte[] balance;
	private static short lengthInfo;
	OwnerPIN pin;
	
	//========= Khao bao bien lien quan xac thuc RSA ========
	private static byte[] sig_buffer;
	private static byte[] privateKeyModule, privateKeyExp;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSign;
	private short sigLen;
	
	//========= Khao bao bien ma hoa AES ========
	private Cipher aesCipher;
	private AESKey aesKey;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new Main(bArray,bOffset,bLength);
	}
	
	protected Main(byte[] bArray, short bOffset, byte bLength) {
		byte aIDLen = bArray[bOffset]; 
		if(aIDLen == 0){
			register();
		}else{
			register(bArray, (short)(bOffset+1), aIDLen);
		}
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		pinCard = new byte[]{0x31,0x32,0x33,0x34};
		pin.update(pinCard, (short) 0, (byte)pinCard.length);
		
		infomation = new byte[1000];
		balance = new byte[]{0x00,0x00,0x00,0x00};
		
		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
		rsaSign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		RSAPrivateKey rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
		
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		encryptPrivateKey(rsaPrivKey, pinCard);
	}
	
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_INSERT_INFO:
			insertInfo(apdu);
			break;
		case INS_READ_INFO:
			readInfo(apdu);
			break;	
		case INS_UNBLOCK_CARD:
			pin.resetAndUnblock();
			break;
		case INS_VERYFY:
			verify(apdu);
			break;
		case INS_CHANGE_PIN:
			changePin(apdu);
			break;	
		case INS_CREDIT:
			credit(apdu);
			break;
		case INS_DEBIT:
			debit(apdu);
			break;
		case INS_GET_BALANCE:
			getBalance(apdu);
			break;
		case INS_SIGN:
			initRSASign(apdu);
			break;
		case INS_READ_PUBLICKEY_EXP:
			getPublicKeyExp(apdu);
			break;
		case INS_READ_PUBLICKEY_MOD:
			getPublicKeyMod(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void insertInfo(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		short dLen = (short)(buffer[ISO7816.OFFSET_LC]&0xFF);
		temp = new byte[dLen];
		short byteRead = (short)(apdu.setIncomingAndReceive());
		short pointer = 0;
		while ( dLen > 0){
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA,temp, pointer, byteRead);
			pointer += byteRead;
			dLen -= byteRead;
			byteRead = apdu.receiveBytes (ISO7816.OFFSET_CDATA );
		}
		lengthInfo = (short)temp.length;
		for(short i = 0 ; i < lengthInfo ; i ++){
			infomation[(short)(i)] = temp[i];
		}
	}
	
	private void readInfo(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		Util.arrayCopy(infomation,(short)0,buffer,(short)0,lengthInfo);
		apdu.setOutgoingAndSend((short)0,lengthInfo);
	}
	
	// Ham nap tien vao tai khoan the
	private void credit(APDU apdu) {
		if (!pin.isValidated()){
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC&0xFF];
		byte byteRead = (byte)(apdu.setIncomingAndReceive()&0xFF);
		if (byteRead != 4){
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		temp = new byte[4];
		Util.arrayCopy(buffer,ISO7816.OFFSET_CDATA,temp,(short)0,byteRead);
		// Lay so tien can nap vao tai khoan
		int creditAmount = byteArrayToShort(temp);
		int currentBalance = byteArrayToShort(balance);
		// Kiem tra so tien nap vao co am hay khong
		if (creditAmount < 0 ){
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		// Cong tien vao tai khoan
		int balan = (int)(currentBalance + creditAmount);
		balance = shortToByteArray(balan);
	}
    
    private void debit(APDU apdu) {
		if (!pin.isValidated()){
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] buffer = apdu.getBuffer();
		byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC&0xFF]);
		byte byteRead = (byte)(apdu.setIncomingAndReceive()&0xFF);
		temp = new byte[4];
		Util.arrayCopy(buffer,ISO7816.OFFSET_CDATA,temp,(short)0,byteRead);
		int debitAmount = byteArrayToShort(temp);
		if ( debitAmount < 0 ){
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		int currentBalance = byteArrayToShort(balance);
		// Kiem tra tai khoan co du dieu kien cho rut hay khong
		if  ((currentBalance - debitAmount) < 0){
			ISOException.throwIt(SW_NEGATIVE_BALANCE);
		}
		int balan = (int)(currentBalance - debitAmount);
		balance = shortToByteArray(balan);
	}
    
    private void getBalance(APDU apdu) {
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] buffer =  apdu.getBuffer();
		apdu.setIncomingAndReceive();
		Util.arrayCopy(balance,(short)0,buffer,(short)0,(short)4);
		apdu.setOutgoingAndSend((short)0,(short)4);
	}
	
	private void verify(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
		if ( pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false ){
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
	}
	
	private void changePin(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		byte byteRead = (byte)(apdu.setIncomingAndReceive()&0xFF);
		temp = new byte[byteRead];
		Util.arrayCopy(buffer,ISO7816.OFFSET_CDATA,temp,(short)0, byteRead);
		
		byte[] pinOld = new byte[pinCard.length];
		
		for(short i = 0; i < pinOld.length; i++){
			pinOld[i] = pinCard[i];
		}
		
		for(short j = 0 ; j < temp.length; j++){
			pinCard[j] = temp[j];
		}

		pin.update(pinCard, (short) 0, (byte)pinCard.length);
		RSAPrivateKey privateKey = decryptPrivateKey(pinOld);
		encryptPrivateKey(privateKey, pinCard);
	}
	
	private void initRSASign(APDU apdu){
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] buffer = apdu.getBuffer();
		short dLen = (short)(buffer[ISO7816.OFFSET_LC]&0xFF);
		byte[] dataVeriRSA = new byte[dLen];
		short byteRead = (short)(apdu.setIncomingAndReceive());
		short pointer = 0;
		while ( dLen > 0){
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, dataVeriRSA, pointer, byteRead);
			pointer += byteRead;
			dLen -= byteRead;
			byteRead = apdu.receiveBytes (ISO7816.OFFSET_CDATA );
		}
		RSAPrivateKey rsaPrivate = decryptPrivateKey(pinCard);
		rsaSign.init(rsaPrivate, Signature.MODE_SIGN);
		sig_buffer = new byte[sigLen];
		rsaSign.sign(dataVeriRSA, (short)0, (short)(dataVeriRSA.length), sig_buffer, (short)0);
		Util.arrayCopy(sig_buffer, (short)0, buffer, (short)0, sigLen);
		apdu.setOutgoingAndSend((short)0, sigLen);
	}
	
	private void getPublicKeyExp(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short length = rsaPubKey.getExponent(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, length);
	}

	private void getPublicKeyMod(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short length = rsaPubKey.getModulus(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, length);
	}
	
	public void deselect() {
    // reset the pin value
		pin.reset();
	}
	
	// Ma hoa privateKey
	private void encryptPrivateKey(RSAPrivateKey privateKey, byte[] cardPin){
		byte[] key = generatorKey(cardPin);
		aesKey.setKey(key, (short)0);
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		byte[] temps = new byte[1024];
		short lengthMod = privateKey.getModulus(temps, (short) 0);
		privateKeyModule = new byte[lengthMod];
		aesCipher.doFinal(temps,(short)0, lengthMod, privateKeyModule, (short) 0);
		
		short lengthExp = privateKey.getExponent(temps, (short)0 );
        privateKeyExp = new byte[lengthExp];
        aesCipher.doFinal(temps,(short)0, lengthExp, privateKeyExp, (short) 0);
        // Xoa key AES khoi the
        aesKey.clearKey();
	}
	
	// Giai ma privateKey
	private RSAPrivateKey decryptPrivateKey(byte[] cardPin){
		byte[] key = generatorKey(cardPin);
		aesKey.setKey(key, (short)0);
		
		byte[] modules = new byte[privateKeyModule.length];
		byte[] exponent = new byte[privateKeyExp.length];
		
		aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(privateKeyModule, (short) 0, (short) privateKeyModule.length, modules, (short) 0x00);
		aesCipher.doFinal(privateKeyExp, (short) 0, (short) privateKeyExp.length, exponent, (short) 0x00);
		
		RSAPrivateKey rsaPrivate = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)(8*sigLen) , false);
		rsaPrivate.setModulus(modules, (short)0,(short) modules.length);
		rsaPrivate.setExponent(exponent, (short)0,(short) exponent.length);
		// Xoa key AES khoi the
		aesKey.clearKey();
		return rsaPrivate;
	}
	
	// Do do dai toi thieu khoa AES la 16 ki tu 
	// nen can x4 lan ma pin de du so ki tu toi thieu cua dau vao khoa k
	private byte[] generatorKey(byte[] cardPin){
		short index = 0;
		byte[] key = new byte[16];
		while(index < 16){
			key[index] = cardPin[0];
			key[(short)(index + 1)] = cardPin[1];
			key[(short)(index + 2)] = cardPin[2];
			key[(short)(index + 3)] = cardPin[3];
			index = (short)(index + 4);
		}
		return key;
	}
	
	private static final int byteArrayToShort(byte[] arrShort) {
		return (int)( arrShort[0]<<24 |
						((arrShort[1]<<24)>>>8 ) | 
						((arrShort[2]<<24)>>>16) | 
						((arrShort[3]<<24)>>>24));
    }

	private static final byte[] shortToByteArray(int value) {
		return new byte[] {
			(byte)(value >>> 24),
			(byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value};
    }

}
