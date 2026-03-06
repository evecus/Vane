<template>
  <span :class="cfg.cls" class="badge text-xs">{{ cfg.label }}</span>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ provider: String })
const cfg = computed(() => {
  const map = {
    cloudflare: { label: 'Cloudflare', cls: 'badge-amber' },
    alidns:     { label: '阿里云', cls: 'badge-blue' },
    dnspod:     { label: 'DNSPod', cls: 'badge-green' },
    tencentcloud: { label: '腾讯云', cls: 'badge-blue' },
  }
  return map[props.provider] || { label: props.provider, cls: 'badge-slate' }
})
</script>
