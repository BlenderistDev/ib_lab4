<?php

/**
 * Шифрование с помощью алгоритма TEA
 */
class Tea 
{

    // магическое значение максимальной константы
    static private $op = 0xffffffff;

    // ключ для шифрования
    private $key = '';

    public function __construct($sKey)
    {
        $this->key = $this->str2long($sKey);
    }
    
    /**
     * Шифруем
     */
    public function encrypt($sText) 
    {
        $iTextLength = strlen($sText);

        $iFillLength = (8-($iTextLength+2))%8 + 2;
        if ($iFillLength<=2 || $iFillLength > 9){
            $iFillLength += 8;
        }

        $sFills = '';
        for ($i = 0; $i < $iFillLength; $i++){
            $sFills .= chr(rand(0,0xff));
        }

        $sText = chr(($iFillLength - 2)|0xF8) . $sFills . $sText;

        $iTmpLength = strlen($sText)+7;
        $sText = pack("a{$iTmpLength}",$sText);

        $tr = pack("a8", '');
        $to = pack("a8", '');
        $sResult = '';
        $o = pack("a8", '');

        for ($i=0; $i < strlen($sText); $i = $i+8){
            $o = $this->xor(substr($sText,$i,8), $tr);
            $tr = $this->xor($this->block_encrypt($o), $to);
            $to = $o;
            $sResult .= $tr;
        }

        return $sResult;
    }

    /**
     * Расшифровываем
     */
    function decrypt($sText)
    {
        $sLength = strlen($sText);

        $prePlain = $this->block_decrypt($sText);
        $pos = (ord($prePlain[0]) & 0x07) + 2;
        $sResult = $prePlain;
        $preCrypt = substr($sText, 0, 8);

        for ($i = 8; $i < $sLength; $i = $i + 8){
            $x = $this->xor(
              $this->block_decrypt($this->xor(
                    substr($sText,$i,$i+8),$prePlain)),
                $preCrypt);
            $prePlain = $this->xor($x, $preCrypt);
            $preCrypt = substr($sText, $i, $i+8);

            $sResult .= $x;
        }

        if (substr($sResult, -7) != pack("a7", '')){
            return "";
        }

        return substr($sResult, $pos+1, -7);
    }

    /**
     * Операция xor
     */
    private function xor($a, $b)
    {
        $a = $this->str2long($a);
        $a1 = $a[0];
        $a2 = $a[1];
        $b = $this->str2long($b);
        $b1 = $b[0];
        $b2 = $b[1];
        return $this->long2str(($a1 ^ $b1) & self::$op). $this->long2str(($a2 ^ $b2) & self::$op);
    }

    /**
     * Шифрование блока
     */
    public function block_encrypt($sText) 
    {
        $s=0;
        $delta=0x9e3779b9;
        $n = 16;

        $sText = $this->str2long($sText);
        $z = $sText[1];
        $y = $sText[0];

        for ($i=0; $i<$n; $i++)
        {
            $s += $delta;
            $y += (self::$op &($z<<4)) + $this->key[0] ^ $z + $s ^ (self::$op&($z>>5))+$this->key[1];
            $y &= self::$op;
            $z += (self::$op &($y<<4)) + $this->key[2] ^ $y + $s ^ (self::$op&($y>>5))+$this->key[3];
            $z &= self::$op;

        }
        return $this->long2str($y).$this->long2str($z);
    }

    /**
     * Расшифровка блока
     */
    public function block_decrypt($sText) 
    {
        $delta=0x9e3779b9;
        $s = ($delta << 4) & self::$op;
        $n=16;

        $sText = $this->str2long($sText);

        $y = $sText[0];
        $z = $sText[1];

        $a = $this->key[0];
        $b = $this->key[1];
        $c = $this->key[2];
        $d = $this->key[3];

        for ($i=0; $i<$n; $i++){
            $z -= (($y<<4) + $c) ^ ($y + $s) ^ (($y>>5) + $d);
            $z &= self::$op;
            $y -= (($z<<4) + $a) ^ ($z + $s) ^ (($z>>5) + $b);
            $y &= self::$op;
            $s -= $delta;
            $s &= self::$op;
        }
        return $this->long2str($y).$this->long2str($z);
    }

    /**
     * Конвертируем строку в long
     */
    private function str2long($data) 
    {
        $tmp = unpack('N*', $data);
        $data_long = array();
        $j = 0;
        foreach ($tmp as $value) {
            $data_long[$j++] = $value;
        }
        return $data_long;
    }

    /**
     * Конвертируем long в строку
     */
    private function long2str($sLength)
    {
        return pack('N', $sLength);
    }
}
$sStr = "programm";
$sPass = "password111ыфав";
$oTea = new Tea($sPass);
$sCryptStr = $oTea->encrypt($sStr, $sPass);
var_dump($sCryptStr);
$sDecryptStr = $oTea->decrypt($sCryptStr, $sPass);
var_dump($sDecryptStr);

?>