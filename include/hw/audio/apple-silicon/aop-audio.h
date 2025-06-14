#ifndef HW_AUDIO_APPLE_SILICON_AOP_AUDIO_H
#define HW_AUDIO_APPLE_SILICON_AOP_AUDIO_H

#include "qemu/osdep.h"
#include "hw/misc/apple-silicon/aop.h"
#include "qom/object.h"

#define TYPE_APPLE_AOP_AUDIO "apple.aop-audio"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAOPAudioState, APPLE_AOP_AUDIO)

SysBusDevice *apple_aop_audio_create(AppleAOPState *aop);

#endif /* HW_AUDIO_APPLE_SILICON_AOP_AUDIO_H */
