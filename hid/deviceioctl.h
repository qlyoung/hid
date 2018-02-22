/*
 * Sensor ioctl emulation.
 */
#pragma once

#define SENSOR_IOCTL_UNKNOWN 0x230008

/* Installs ioctl hooks. Should be called on DLL attach. */
void installhooks();
