#include "main.h"
#include <stdio.h>
#include <string.h>

#define AES_TEXT_SIZE 16
#define ECB 1
#define CBC 2
#define CTR 3

/*
  In ~/Library/Arduino15/packages/STMicroelectronics/hardware/stm32/2.5.0/system/Drivers/STM32WLxx_HAL_Driver/Inc/stm32wlxx_hal_cryp.h
  and ~/Library/Arduino15/packages/STMicroelectronics/hardware/stm32/2.5.0/system/Drivers/STM32WLxx_HAL_Driver/Src/stm32wlxx_hal_cryp.c
  change the B0 instances to BB0 or something else – B0 is already taken by ~/Library/Arduino15/packages/STMicroelectronics/hardware/stm32/2.5.0/cores/arduino/binary.h
*/


CRYP_HandleTypeDef hcryp;
__ALIGN_BEGIN static const uint32_t pKeyAES[4] __ALIGN_END = {
  0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C
};
/* Key size 256 bits */
uint32_t aAES256key[8] = { 0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4 };

/* Initialization vector */
uint32_t AESIV[4] = { 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F };
uint32_t AESIV_CTR[4] = { 0xF0F1F2F3, 0xF4F5F6F7, 0xF8F9FAFB, 0xFCFDFEFF };

/* Plaintext */
uint32_t aPlaintextECB[AES_TEXT_SIZE] = {
  0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,
  0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF, 0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710
};

uint32_t aPlaintextCBC[AES_TEXT_SIZE] = {
  0xE2BEC16B, 0x969F402E, 0x117E3DE9, 0x2A179373, 0x578A2DAE, 0x9CAC031E, 0xAC6FB79E, 0x518EAF45,
  0x461CC830, 0x11E45CA3, 0x19C1FBE5, 0xEF520A1A, 0x45249FF6, 0x179B4FDF, 0x7B412BAD, 0x10376CE6
};

uint32_t aPlaintextCTR[AES_TEXT_SIZE] = {
  0x477D83D6, 0x69F90274, 0x887EBC97, 0x54E8C9CE, 0xEA51B475, 0x3935C078, 0x35F6ED79, 0x8A71F5A2,
  0x6238130C, 0x88273AC5, 0x9883DFA7, 0xF74A5058, 0xA224F96F, 0xE8D9F2FB, 0xDE82D4B5, 0x08EC3667
};

/* AES_ECB */
/* Expected text: Encrypted Data with AES 128 Mode ECB */
uint32_t aEncryptedtextECB128[AES_TEXT_SIZE] = {
  0x3AD77BB4, 0x0D7A3660, 0xA89ECAF3, 0x2466EF97, 0xF5D3D585, 0x03B9699D, 0xE785895A, 0x96FDBAAF,
  0x43B1CD7F, 0x598ECE23, 0x881B00E3, 0xED030688, 0x7B0C785E, 0x27E8AD3F, 0x82232071, 0x04725DD4
};

/*AES_CBC*/
/* Expected text: Encrypted Data with AES 128 Mode CBC */
uint32_t aEncryptedtextCBC128[AES_TEXT_SIZE] = {
  0xACAB4976, 0x46B21981, 0x9B8EE9CE, 0x7D19E912, 0x9BCB8650, 0xEE197250, 0x3A11DB95, 0xB2787691,
  0xB8D6BE73, 0x3B74C1E3, 0x9EE61671, 0x16952222, 0xA1CAF13F, 0x09AC1F68, 0x30CA0E12, 0xA7E18675
};

/*AES_CTR*/
/* Expected text: Encrypted Data with AES 128 Mode CTR */
uint32_t aEncryptedtextCTR128[AES_TEXT_SIZE] = {
  0x8986B2E1, 0x64C7046D, 0x2616F7D8, 0x736DB099, 0xD66F6019, 0xFFBF0E9E, 0xDE18E861, 0xFFBFFF9D,
  0x7CFB275A, 0x7ACBABDB, 0x4090F2DA, 0xD57C0DB0, 0x5BB8C078, 0x8BC07DF4, 0x050E849E, 0x773900CF
};

/* Expected text: Encrypted Data with AES 256 Mode ECB */
uint32_t aEncryptedtextECB256[AES_TEXT_SIZE] = {
  0xF3EED1BD, 0xB5D2A03C, 0x064B5A7E, 0x3DB181F8, 0x591CCB10, 0xD410ED26, 0xDC5BA74A, 0x31362870,
  0xB6ED21B9, 0x9CA6F4F9, 0xF153E7B1, 0xBEAFED1D, 0x23304B7A, 0x39F9F3FF, 0x067D8D8F, 0x9E24ECC7
};

/* Expected text: Encrypted Data with AES 256 Mode CBC */
uint32_t aEncryptedtextCBC256[AES_TEXT_SIZE] = {
  0x044C8CF5, 0xBAF1E5D6, 0xFBAB9E77, 0xD6FB7B5F, 0x964EFC9C, 0x8D80DB7E, 0x7B779F67, 0x7D2C70C6,
  0x6933F239, 0xCFBAD9A9, 0x63E230A5, 0x61142304, 0xE205EBB2, 0xFCE99BC3, 0x07196CDA, 0x1B9D6A8C
};

/* Expected text: Encrypted Data with AES 256 Mode CTR */
uint32_t aEncryptedtextCTR256[AES_TEXT_SIZE] = {
  0xC8C37806, 0xA591EAEE, 0x20AFE5ED, 0x144BCFDD, 0x53C7C22F, 0x59AD46B2, 0x09972153, 0xA3AF5353,
  0x5B0C90D4, 0x3297BC45, 0x5DE80E17, 0xB11921B4, 0xB1A393FB, 0x65B55E6D, 0x10BB43C8, 0x65829EA2
};

/* Used for storing the encrypted text */
uint32_t aEncryptedtext[AES_TEXT_SIZE];
/* Used for storing the decrypted text */
uint32_t aDecryptedtext[AES_TEXT_SIZE];
char msg[256];
UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_AES_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */
void SystemClock_Config(void);
void data_cmp(uint32_t *EncryptedText, uint32_t *RefText, uint8_t Size);
void hexDump(uint8_t *buf, uint16_t len);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#define TIMEOUT_VALUE 0xFF
// #define USE_USART1_TOO
// Uncomment the above define if you need to output to USART1
/* USER CODE END 0 */

void logString() {
  uint8_t ln = strlen(msg);
#if defined(USE_USART1_TOO)
  HAL_UART_Transmit(&huart1, (uint8_t*) msg, ln, 1000);
#endif
  HAL_UART_Transmit(&huart2, (uint8_t*) msg, ln, 1000);
}

void setup() {
  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();
  /* Configure the system clock */
  SystemClock_Config();
  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_AES_Init();
  MX_USART1_UART_Init();
  MX_USART2_UART_Init();
  HAL_Delay(1000);
  /* USER CODE BEGIN 2 */
  /*##- Configure the CRYP peripheral ######################################*/
  /* Set the common CRYP parameters */
  sprintf(msg, "Start!\n");
  logString();
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, GPIO_PIN_SET); // Green LED on
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, GPIO_PIN_SET); // Blue LED off
  hcryp.Instance = AES;
  sprintf(msg, "\n=====================================================");
  logString();
  sprintf(msg, "\n                      # ECB #");
  logString();
  sprintf(msg, "\n=====================================================\n");
  logString();
  /* Display Plain Data*/
  sprintf(msg, "Plaintext:\n");
  logString();
  hexDump((uint8_t*) aPlaintextECB, AES_TEXT_SIZE * 4);
  /******************************************************************************/
  /*                             AES mode ECB                                   */
  /******************************************************************************/
  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) myError_Handler();
  /*=====================================================
    Encryption ECB mode
    ======================================================*/
  /*****************  AES 128   ****************/
  /* Initialize the CRYP peripheral */
  sprintf(msg, "AES 128:\n");
  logString();
  sprintf(msg, "Expected cyphertext:\n");
  logString();
  hexDump((uint8_t*) aEncryptedtextECB128, AES_TEXT_SIZE * 4);
  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_ECB;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  HAL_StatusTypeDef ret;
  size_t rounds = 0;
  uint32_t future_tick_time = HAL_GetTick() + 1000;
  while (HAL_GetTick() < future_tick_time) {
    ret = HAL_CRYP_Encrypt(&hcryp, aPlaintextECB, AES_TEXT_SIZE, aEncryptedtext, TIMEOUT_VALUE);
    rounds += 1;
  }
  if (ret != HAL_OK) myError_Handler();
  /* Display encrypted Data */
  sprintf(msg, "Encrypted:\n");
  logString();
  sprintf(msg, "%u rounds in 1 sec\n", rounds);
  logString();
  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  /* Compare the encrypted text with the expected one *************************/
  data_cmp(aEncryptedtext, aEncryptedtextECB128, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  sprintf(msg, "AES 256:\n");
  //  logString();
  //  sprintf(msg, "Expected cyphertext:\n");
  //  logString();
  //  hexDump((uint8_t*) aEncryptedtextECB256, AES_TEXT_SIZE * 4);
  //  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  rounds = 0;
  //  future_tick_time = HAL_GetTick() + 1000;
  //  while (HAL_GetTick() < future_tick_time) {
  //    ret = HAL_CRYP_Encrypt_IT(&hcryp, aPlaintextECB, AES_TEXT_SIZE, aEncryptedtext);
  //    rounds += 1;
  //    /* Wait for processing to be done */
  //    while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  //  }
  //  if (ret != HAL_OK) myError_Handler();
  //  /* Display encrypted Data */
  //  sprintf(msg, "Encrypted:\n");
  //  logString();
  //  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  //  logString();
  //  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  //  // Display_EncryptedData(ECB, 256, AES_TEXT_SIZE);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aEncryptedtext, aEncryptedtextECB256, AES_TEXT_SIZE);
  //  /*=====================================================
  //    Decryption ECB mode
  //    ======================================================*/
  //  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) {
  //    myError_Handler();
  //  }
  /*****************  AES 128   ****************/
  sprintf(msg, "AES 128:\n");
  logString();
  /* Initialize the CRYP peripheral */
  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_ECB;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  /* Start decrypting aCyphertext, the decrypted data is available in aDecryptedtext */
  rounds = 0;
  future_tick_time = HAL_GetTick() + 1000;
  while (HAL_GetTick() < future_tick_time) {
    ret = HAL_CRYP_Decrypt(&hcryp, aEncryptedtextECB128, AES_TEXT_SIZE, aDecryptedtext, TIMEOUT_VALUE);
    rounds += 1;
  }
  if (ret != HAL_OK) myError_Handler();
  /* Display decrypted Data */
  sprintf(msg, "Decrypted:\n");
  logString();
  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  logString();
  hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  // Display_DecryptedData(ECB, 128, AES_TEXT_SIZE);
  /* Check the encrypted text with the expected one *************************/
  data_cmp(aDecryptedtext, aPlaintextECB, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  sprintf(msg, "AES 256:\n");
  //  logString();
  //  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  rounds = 0;
  //  future_tick_time = HAL_GetTick() + 1000;
  //  while (HAL_GetTick() < future_tick_time) {
  //    ret = HAL_CRYP_Decrypt_IT(&hcryp, aEncryptedtextECB256, AES_TEXT_SIZE, aDecryptedtext);
  //    rounds += 1;
  //    /* Wait for processing to be done */
  //    while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  //  }
  //  if (ret != HAL_OK) myError_Handler();
  //  /* Display decrypted Data */
  //  sprintf(msg, "Decrypted:\n");
  //  logString();
  //  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  //  logString();
  //  hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  //  /* Display decrypted Data */
  //  // Display_DecryptedData(ECB, 256, AES_TEXT_SIZE);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aDecryptedtext, aPlaintextECB, AES_TEXT_SIZE);
  /******************************************************************************/
  /*                             AES mode CBC                                   */
  /******************************************************************************/
  sprintf(msg, "\n=====================================================");
  logString();
  sprintf(msg, "\n                      # CBC #");
  logString();
  sprintf(msg, "\n=====================================================\n");
  logString();
  /* Display Plain Data*/
  sprintf(msg, "Plaintext:\n");
  logString();
  hexDump((uint8_t*) aPlaintextCBC, AES_TEXT_SIZE * 4);
  /* Display Cypher Data*/
  sprintf(msg, "Cyphertext:\n");
  logString();
  hexDump((uint8_t*) aEncryptedtextCBC128, AES_TEXT_SIZE * 4);
  /*=====================================================
    Encryption CBC mode
    ======================================================*/
  sprintf(msg, "AES 128:\n");
  logString();
  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) myError_Handler();
  /*****************  AES 128   ****************/
  /* Initialize the CRYP peripheral */
  hcryp.Init.DataType = CRYP_DATATYPE_8B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_CBC;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.pInitVect = AESIV;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  rounds = 0;
  future_tick_time = HAL_GetTick() + 1000;
  while (HAL_GetTick() < future_tick_time) {
    ret = HAL_CRYP_Encrypt(&hcryp, aPlaintextCBC, AES_TEXT_SIZE, aEncryptedtext, TIMEOUT_VALUE);
    rounds += 1;
  }
  if (ret != HAL_OK) myError_Handler();
  /* Display encrypted Data */
  sprintf(msg, "Encrypted:\n");
  logString();
  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  logString();
  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  /* Check the encrypted text with the expected one *************************/
  data_cmp(aEncryptedtext, aEncryptedtextCBC128, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  sprintf(msg, "AES 256:\n");
  //  logString();
  //  hcryp.Init.DataType = CRYP_DATATYPE_8B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  rounds = 0;
  //  future_tick_time = HAL_GetTick() + 1000;
  //  while (HAL_GetTick() < future_tick_time) {
  //    ret = HAL_CRYP_Encrypt_IT(&hcryp, aPlaintextCBC, AES_TEXT_SIZE, aEncryptedtext);
  //    rounds += 1;
  //    while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY);
  //  }
  //  if (ret != HAL_OK) myError_Handler();
  //  /* Display encrypted Data */
  //  sprintf(msg, "Encrypted:\n");
  //  logString();
  //  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  //  logString();
  //  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aEncryptedtext, aEncryptedtextCBC256, AES_TEXT_SIZE);
  /*=====================================================
    Decryption CBC mode
    ======================================================*/
  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) myError_Handler();
  /*****************  AES 128   ****************/
  sprintf(msg, "AES 128:\n");
  logString();
  /* Initialize the CRYP peripheral */
  hcryp.Init.DataType = CRYP_DATATYPE_8B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_CBC;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.pInitVect = AESIV;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  rounds = 0;
  future_tick_time = HAL_GetTick() + 1000;
  while (HAL_GetTick() < future_tick_time) {
    ret = HAL_CRYP_Decrypt(&hcryp, aEncryptedtextCBC128, AES_TEXT_SIZE, aDecryptedtext, TIMEOUT_VALUE);
    rounds += 1;
  }
  if (ret != HAL_OK) myError_Handler();
  /* Display encrypted Data */
  sprintf(msg, "Decrypted:\n");
  logString();
  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  logString();
  hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  /* Check the encrypted text with the expected one *************************/
  data_cmp(aDecryptedtext, aPlaintextCBC, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  sprintf(msg, "AES 256:\n");
  //  logString();
  //  hcryp.Init.DataType = CRYP_DATATYPE_8B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  rounds = 0;
  //  future_tick_time = HAL_GetTick() + 1000;
  //  while (HAL_GetTick() < future_tick_time) {
  //    ret = HAL_CRYP_Decrypt_IT(&hcryp, aEncryptedtextCBC256, AES_TEXT_SIZE, aDecryptedtext);
  //    rounds += 1;
  //    /* Wait for processing to be done */
  //    while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  //  }
  //  if (ret != HAL_OK) myError_Handler();
  //  /* Display decrypted Data */
  //  sprintf(msg, "Decrypted:\n");
  //  logString();
  //  sprintf(msg, "%d rounds in 1 sec\n", rounds);
  //  logString();
  //  hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aDecryptedtext, aPlaintextCBC, AES_TEXT_SIZE);
  /******************************************************************************/
  /*                             AES mode CTR                                   */
  /******************************************************************************/
  sprintf(msg, "\n=====================================================");
  logString();
  sprintf(msg, "\n                      # CTR #");
  logString();
  sprintf(msg, "\n=====================================================\n");
  logString();
  /* Display Plain Data*/
  sprintf(msg, "Plaintext:\n");
  logString();
  hexDump((uint8_t*) aPlaintextCTR, AES_TEXT_SIZE * 4);
  /*=====================================================
    Encryption CTR mode
    ======================================================*/
  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) myError_Handler();
  /*****************  AES 128   ****************/
  sprintf(msg, "AES 128:\n");
  logString();
  sprintf(msg, "Expected cyphertext:\n");
  logString();
  hexDump((uint8_t*) aEncryptedtextCTR128, AES_TEXT_SIZE * 4);
  /* Initialize the CRYP peripheral */
  hcryp.Init.DataType = CRYP_DATATYPE_1B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_CTR;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.pInitVect = AESIV_CTR;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  /* Start encrypting aPlaintextCTR, the cypher data is available in aEncryptedtext */
  rounds = 0;
  future_tick_time = HAL_GetTick() + 1000;
  while (HAL_GetTick() < future_tick_time) {
    ret = HAL_CRYP_Encrypt(&hcryp, aPlaintextCTR, AES_TEXT_SIZE, aEncryptedtext, TIMEOUT_VALUE);
    rounds += 1;
    /* Wait for processing to be done */
    while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  }
  if (ret != HAL_OK) myError_Handler();
  sprintf(msg, "Encrypted:\n");
  logString();
  sprintf(msg, "%u rounds in 1 sec\n", rounds);
  logString();
  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  /* Check the encrypted text with the expected one *************************/
  data_cmp(aEncryptedtext, aEncryptedtextCTR128, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  sprintf(msg, "AES 256:\n");
  //  logString();
  //  sprintf(msg, "Expected cyphertext:\n");
  //  logString();
  //  hexDump((uint8_t*) aEncryptedtextCTR256, AES_TEXT_SIZE * 4);
  //  hcryp.Init.DataType = CRYP_DATATYPE_1B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  if (HAL_CRYP_Encrypt_IT(&hcryp, aPlaintextCTR, AES_TEXT_SIZE, aEncryptedtext) != HAL_OK) myError_Handler();
  //  /* Wait for processing to be done */
  //  while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  //  /* Display encrypted Data */
  //  sprintf(msg, "Encrypted:\n");
  //  logString();
  //  hexDump((uint8_t*) aEncryptedtext, AES_TEXT_SIZE * 4);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aEncryptedtext, aEncryptedtextCTR256, AES_TEXT_SIZE);
  /*=====================================================
    Decryption CTR mode
    ======================================================*/
  if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) myError_Handler();
  /*****************  AES 128   ****************/
  /* Initialize the CRYP peripheral */
  hcryp.Init.DataType = CRYP_DATATYPE_1B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.Algorithm = CRYP_AES_CTR;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.pInitVect = AESIV_CTR;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  /* Start decrypting aCyphertext, the decrypted data is available in aDecryptedtext */
  if (HAL_CRYP_Decrypt(&hcryp, aEncryptedtextCTR128, AES_TEXT_SIZE, aDecryptedtext, TIMEOUT_VALUE) == HAL_OK) {
    /* Display decrypted Data */
    sprintf(msg, "Decrypted:\n");
    logString();
    hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  } else {
    /* Processing Error */
    myError_Handler();
  }
  /* Check the encrypted text with the expected one *************************/
  data_cmp(aDecryptedtext, aPlaintextCTR, AES_TEXT_SIZE);
  //  /*****************  AES 256   ****************/
  //  hcryp.Init.DataType = CRYP_DATATYPE_1B;
  //  hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
  //  hcryp.Init.pKey = aAES256key;
  //  /* Set the CRYP parameters */
  //  if (HAL_CRYP_Init(&hcryp) != HAL_OK) myError_Handler();
  //  if (HAL_CRYP_Decrypt_IT(&hcryp, aEncryptedtextCTR256, AES_TEXT_SIZE, aDecryptedtext) != HAL_OK) myError_Handler();
  //  /* Wait for processing to be done */
  //  while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) ;
  //  /* Display decrypted Data */
  //  sprintf(msg, "Decrypted:\n");
  //  logString();
  //  hexDump((uint8_t*) aDecryptedtext, AES_TEXT_SIZE * 4);
  //  /* Check the encrypted text with the expected one *************************/
  //  data_cmp(aDecryptedtext, aPlaintextCTR, AES_TEXT_SIZE);
  strcmp(msg, "===================================================\n ");
  logString();
  strcmp(msg, "\n\r ECB, CBC and CTR encryptions/decryptions done.\n ");
  logString();
  strcmp(msg, "No issue detected.\n ");
  logString();
  /* USER CODE END 2 */
  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, GPIO_PIN_RESET); // Green LED off
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, GPIO_PIN_RESET); // Blue LED off
  HAL_Delay(1000);
  while (1) {
    /* USER CODE END WHILE */
    HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_0); // Toggle the state of pin PA0 Green LED
    HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_1); // Toggle the state of pin PA1 Blue LED
    HAL_Delay(1000);
    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  @brief System Clock Configuration
  @retval None
*/
void SystemClock_Config(void) {
  RCC_OscInitTypeDef RCC_OscInitStruct = { 0 };
  RCC_ClkInitTypeDef RCC_ClkInitStruct = { 0 };
  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_11;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    myError_Handler();
  /** Configure the SYSCLKSource, HCLK, PCLK1 and PCLK2 clocks dividers
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK3 | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_MSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.AHBCLK3Divider = RCC_SYSCLK_DIV1;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
    myError_Handler();
}

/**
  @brief AES Initialization Function
  @param None
  @retval None
*/
static void MX_AES_Init(void) {
  /* USER CODE BEGIN AES_Init 0 */
  /* USER CODE END AES_Init 0 */
  /* USER CODE BEGIN AES_Init 1 */
  /* USER CODE END AES_Init 1 */
  hcryp.Instance = AES;
  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.pKey = (uint32_t*) pKeyAES;
  hcryp.Init.Algorithm = CRYP_AES_ECB;
  hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
  hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
  hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK)
    myError_Handler();
  /* USER CODE BEGIN AES_Init 2 */
  /* USER CODE END AES_Init 2 */
}

/**
  @brief USART2 Initialization Function
  @param None
  @retval None
*/
static void MX_USART2_UART_Init(void) {
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
    myError_Handler();
  //  if (HAL_UARTEx_SetTxFifoThreshold(&huart2, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK) myError_Handler();
  //  if (HAL_UARTEx_SetRxFifoThreshold(&huart2, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK) myError_Handler();
  //  if (HAL_UARTEx_DisableFifoMode(&huart2) != HAL_OK) myError_Handler();
  /* Peripheral interrupt init*/
}

/**
  @brief USART1 Initialization Function
  @param None
  @retval None
*/
static void MX_USART1_UART_Init(void) {
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
    myError_Handler();
  //  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK) myError_Handler();
  //  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK) myError_Handler();
  //  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK) myError_Handler();
  /* Peripheral interrupt init*/
}

/**
  @brief GPIO Initialization Function
  @param None
  @retval None
*/
static void MX_GPIO_Init(void) {
  GPIO_InitTypeDef GPIO_InitStruct = { 0 };
  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();
  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0 | GPIO_PIN_1, GPIO_PIN_RESET);
  /*Configure GPIO pins : PA0 PA1 */
  GPIO_InitStruct.Pin = GPIO_PIN_0 | GPIO_PIN_1;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}

/**
  @brief  buffer data comparison
  @param
  @retval None
*/
void data_cmp(uint32_t *EncryptedText, uint32_t *RefText, uint8_t Size) {
  /*  Before starting a new process, you need to check the current state of the peripheral;
    if it is busy you need to wait for the end of current transfer before starting a new one.
    For simplicity reasons, this example is just waiting till the end of the
    process, but application may perform other tasks while transfer operation
    is ongoing. */
  while (HAL_CRYP_GetState(&hcryp) != HAL_CRYP_STATE_READY) {
  }
  /*##-3- Check the encrypted text with the expected one #####################*/
  if (memcmp(EncryptedText, RefText, Size * 4) != 0) {
    myError_Handler();
  } else {
    sprintf((char*) msg, " [o] Pass.\n");
    logString();
  }
}

void hexDump(uint8_t *buf, uint16_t len) {
  // Something similar to the Unix/Linux hexdump -C command
  // Pretty-prints the contents of a buffer, 16 bytes a row
  char alphabet[17] = "0123456789abcdef";
  uint16_t i;
  sprintf((char*) msg, "   +------------------------------------------------+ +----------------+\n");
  logString();
  sprintf((char*) msg, "   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |\n");
  logString();
  for (i = 0; i < len; i += 16) {
    if (i % 128 == 0) {
      sprintf((char*) msg, "   +------------------------------------------------+ +----------------+\n");
      logString();
    }
    char s[] = "|                                                | |                |\n";
    // pre-formated line. We will replace the spaces with text when appropriate.
    uint8_t ix = 1, iy = 52, j;
    for (j = 0; j < 16; j++) {
      if (i + j < len) {
        uint8_t c = buf[i + j];
        // fastest way to convert a byte to its 2-digit hex equivalent
        s[ix++] = alphabet[(c >> 4) & 0x0F];
        s[ix++] = alphabet[c & 0x0F];
        ix++;
        if (c > 31 && c < 127) s[iy++] = c;
        else s[iy++] = '.'; // display ASCII code 0x20-0x7F or a dot.
      }
    }
    // display line number then the text
    sprintf(msg, "% 2x.%s", i, s);
    logString();
  }
  sprintf((char*) msg, "   +------------------------------------------------+ +----------------+\n");
  logString();
}

/* USER CODE END 4 */


/**
  @brief  This function is executed in case of error occurrence.
  @retval None
*/
void myError_Handler() {
  /* USER CODE BEGIN myError_Handler_Debug */
  // the pre-defined Error_Handler() gives me heartburn, even prefixed with weak__
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_0, GPIO_PIN_RESET); // Green LED off
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_1, GPIO_PIN_RESET); // Blue LED on
  HAL_Delay(100);
  while (1) {
    HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_0); // Toggle the state of pin PA0
    HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_1); // Toggle the state of pin PA1
    HAL_Delay(100);
  }
  /* USER CODE END myError_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
    @brief  Reports the name of the source file and the source line number
            where the assert_param error has occurred.
    @param  file: pointer to the source file name
    @param  line: assert_param error line source number
    @retval None
*/
void assert_failed(uint8_t *file, uint32_t line) {
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

void loop() {
}
