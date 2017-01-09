package dukpt.util;

import java.math.BigInteger;

public class ByteArrayUtil {
	public static byte[] padLeftWithZeroes(byte[] byteArray, int length) {
		byte[] newByteArray = new byte[length];
		int offset = length - byteArray.length;
		for(int i = 0; i < offset; i++) {
			newByteArray[i] = (byte)0x00;
		}
		
		for(int i = 0, j = offset; i < byteArray.length; i ++) {
			newByteArray[j++] = byteArray[i];
		}
		
		return newByteArray;
	}
	
	public static byte[] padLeftWith0xFF(byte[] byteArray, int length) {
		byte[] newByteArray = new byte[length];
		int offset = length - byteArray.length;
		for(int i = 0; i < offset; i++) {
			newByteArray[i] = (byte)0xFF;
		}
		
		for(int i = 0, j = offset; i < byteArray.length; i ++) {
			newByteArray[j++] = byteArray[i];
		}
		
		return newByteArray;
	}
	
	public static byte[] and(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a & b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] or(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a | b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] xor(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a ^ b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] subArray(byte[] array, int from, int to) {
		int length = (to - from) + 1;
		byte[] subArray = new byte[length];
		
		for(int i = 0, j = from; j < to + 1; i++, j++) {
			subArray[i] = array[j];
		}
		
		return subArray;
	}
	
	public static byte[] join(byte[] left, byte[] right) {
		byte[] result = new byte[left.length + right.length];
		
		for(int i = 0; i < left.length; i ++) {
			result[i] = left[i];
		}
		
		for(int i = 0; i < right.length; i ++) {
			result[i + left.length] = right[i];
		}
		
		return result;
	}

	public static byte[] shiftRight(byte[] byteArray, int n) {
		byte[] newArray = new byte[byteArray.length];
		
		BigInteger intFromOfArray = new BigInteger(byteArray);
		intFromOfArray = intFromOfArray.shiftRight(n);
		
		byte[] intToArray = intFromOfArray.toByteArray();
		if(intToArray.length < newArray.length) {
			int offset = newArray.length - intToArray.length;
			for(int i = 0; i < offset; i ++) {
				newArray[i] = 0x00;
			}
			
			for(int i = offset, j = 0; i < newArray.length; i++, j++) {
				newArray[i] = intToArray[j];
			}
		}
		
		return newArray;
	}
}
