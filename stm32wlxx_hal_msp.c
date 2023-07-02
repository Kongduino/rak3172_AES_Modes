/* USER CODE BEGIN Header */
/**
  ******************************************************************************
    @file         stm32wlxx_hal_msp.c
    @brief        This file provides code for the MSP Initialization
                  and de-Initialization codes.
  ******************************************************************************
    @attention

    <h2><center>&copy; Copyright (c) 2022 STMicroelectronics.
    All rights reserved.</center></h2>

    This software component is licensed by ST under BSD 3-Clause license,
    the "License"; You may not use this file except in compliance with the
    License. You may obtain a copy of the License at:
                           opensource.org/licenses/BSD-3-Clause

  ******************************************************************************
*/
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN Define */

/* USER CODE END Define */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN Macro */

/* USER CODE END Macro */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* External functions --------------------------------------------------------*/
/* USER CODE BEGIN ExternalFunctions */

/* USER CODE END ExternalFunctions */

/* USER CODE BEGIN 0 */

/* USER CODE END 0 */
/**
    Initializes the Global MSP.
*/
void HAL_MspInit(void) {
  /* USER CODE BEGIN MspInit 0 */
  /* USER CODE END MspInit 0 */
  /* System interrupt init*/
  /* USER CODE BEGIN MspInit 1 */
  /* USER CODE END MspInit 1 */
}

/**
  @brief CRYP MSP Initialization
  This function configures the hardware resources used in this example
  @param hcryp: CRYP handle pointer
  @retval None
*/
void HAL_CRYP_MspInit(CRYP_HandleTypeDef* hcryp) {
  if (hcryp->Instance == AES) {
    /* USER CODE BEGIN AES_MspInit 0 */
    /* USER CODE END AES_MspInit 0 */
    /* Peripheral clock enable */
    __HAL_RCC_AES_CLK_ENABLE();
    /* AES interrupt Init */
    HAL_NVIC_SetPriority(AES_IRQn, 0, 0);
    HAL_NVIC_EnableIRQ(AES_IRQn);
    /* USER CODE BEGIN AES_MspInit 1 */
    /* USER CODE END AES_MspInit 1 */
  }

}

/**
  @brief CRYP MSP De-Initialization
  This function freeze the hardware resources used in this example
  @param hcryp: CRYP handle pointer
  @retval None
*/
void HAL_CRYP_MspDeInit(CRYP_HandleTypeDef* hcryp) {
  if (hcryp->Instance == AES) {
    /* USER CODE BEGIN AES_MspDeInit 0 */
    /* USER CODE END AES_MspDeInit 0 */
    /* Peripheral clock disable */
    __HAL_RCC_AES_CLK_DISABLE();
    /* AES interrupt DeInit */
    HAL_NVIC_DisableIRQ(AES_IRQn);
    /* USER CODE BEGIN AES_MspDeInit 1 */
    /* USER CODE END AES_MspDeInit 1 */
  }

}

/**
  @brief UART MSP Initialization
  This function configures the hardware resources used in this example
  @param huart: UART handle pointer
  @retval None
*/
void HAL_UART_MspInit(UART_HandleTypeDef* huart) {
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct = {0};
  if (huart->Instance == USART2) {
    /* USER CODE BEGIN USART2_MspInit 0 */
    /* USER CODE END USART2_MspInit 0 */
    /** Initializes the peripherals clocks
    */
    PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_USART2;
    PeriphClkInitStruct.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK) Error_Handler();
    /* Peripheral clock enable */
    __HAL_RCC_USART2_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    /**USART2 GPIO Configuration
      PA3     ------> USART2_RX
      PA2     ------> USART2_TX
    */
    GPIO_InitStruct.Pin = GPIO_PIN_3 | GPIO_PIN_2;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
    /* USER CODE BEGIN USART2_MspInit 1 */
    /* USER CODE END USART2_MspInit 1 */
  }

}

/**
  @brief UART MSP De-Initialization
  This function freeze the hardware resources used in this example
  @param huart: UART handle pointer
  @retval None
*/
void HAL_UART_MspDeInit(UART_HandleTypeDef* huart) {
  if (huart->Instance == USART2) {
    /* USER CODE BEGIN USART2_MspDeInit 0 */
    /* USER CODE END USART2_MspDeInit 0 */
    /* Peripheral clock disable */
    __HAL_RCC_USART2_CLK_DISABLE();
    /**USART2 GPIO Configuration
      PA3     ------> USART2_RX
      PA2     ------> USART2_TX
    */
    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_3 | GPIO_PIN_2);
    /* USER CODE BEGIN USART2_MspDeInit 1 */
    /* USER CODE END USART2_MspDeInit 1 */
  }

}

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */
