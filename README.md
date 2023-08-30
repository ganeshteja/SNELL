# SNELL
Code for the implementation and testing of Selective Authenticated Pilot Location Disclosure for Remote ID-enabled Drones (SNELL) protocol on ESP32 microcontroller in Arduino platform (Windows OS). 


## Installation 
- The Code is implemented in Arduino IDE for ESP32. So please [download](https://www.arduino.cc/en/software) and install the Arduino software and also [add support for ESP32 boards in Arduino](https://randomnerdtutorials.com/installing-the-esp32-board-in-arduino-ide-windows-instructions/).
- You need to install the [ESP32 sketch data upload Tool](https://randomnerdtutorials.com/install-esp32-filesystem-uploader-arduino-ide/) to upload your precomputed files to the ESP32 File System.
- Next copy the Schnorr and MIRACL_BN254 libraries from the Libraries folder to your Arduino libraries folder. 
> **_NOTE:_** The Schnorr library that I made uses SECP256k1 curve but if you want to use other curves you can modify the library by taking a look at the codes in [components] (components/Schnorr)

## Testing

- The codes for all three modes work out of the box. Depending on the mode, you need to perform a few steps to test the SNELL protocol.

### Fully Precomputed Mode
I have provided data files with precomputed CP-ABE data and the symmetric keys for various number of attributes in the Access Control Policy (n=2 to n=13) each named as dataX or dataXX where X/XX represents the number of attributes. 
- First clear the Files System on ESP32 by uploading empty Data folder using the ESP32 sketch data upload tool.
- Copy one of these data files into the Data folder in the arduino sketch folder "precompute". If there is another file already in this folder, you can replace it. 
- Now you can upload the code and the file to the ESP32 board. debug information is printed in Serial monitor.
- I have provided modified python files (ipynb) of the SNELL implementation and you can use that to generate the precomputed data files for your custom Access policies.

### Partially Precomputed Mode
In this mode, the ephemeral random nonces are precomputed and store on the ESP32. 
- First clear the Files System on ESP32 by uploading empty Data folder using the ESP32 sketch data upload tool.
- Now run the "precompute_rnonce.ino" sketch. This generates 100 rnonces and stores them in a file on ESP32.
- Now you can upload the "rn_precompute23.ino" sketch which has an Access Policy with 23 attributes. 

### Parallel Computed Mode
This mode does not have any prerequisite steps. You can run the sketch directly.

### Modifying Access Control Policy
- To moify the access policy, if the number of attributes in your custom policy is the same as the one in the code, you just need to change the following lines. Replace the Policy array with you own policy and replace the attributes array with your attributes.
 ```sh
char policy[]
char attributes[arraySize][5]
```
- If the number of attributes in your custom policy is differnet from the one in the code, you can copy the following four intializations from the attributes.txt file into your code and modify the Policy and attributes arrays as mentioned in the previous point.

```sh
const int arraySize
int rows[arraySize][arraySize]
char policy[]
char attributes[arraySize][5]
```

### BLS12-381 
You can test the implementation using BLS12-381 curve by follow the same steps mentioned in the previous section. The Partially Precomputed Mode and Parallel Computed Mode implementations are available in the BLS12-381 folder. 
