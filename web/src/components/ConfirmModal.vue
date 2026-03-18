<template>
  <Teleport to="body">
    <Transition name="confirm-fade">
      <div v-if="modelValue"
           class="fixed inset-0 z-50 flex items-center justify-center p-4"
           style="background:rgba(0,0,0,0.35);backdrop-filter:blur(4px)"
           @click.self="$emit('update:modelValue', false)">
        <div class="bg-white rounded-2xl shadow-2xl w-full max-w-sm p-6 animate-confirm-in">
          <!-- 图标 -->
          <div class="flex items-center justify-center w-12 h-12 rounded-2xl bg-red-50 mx-auto mb-4">
            <Trash2 :size="22" class="text-red-500" />
          </div>
          <!-- 文字 -->
          <h3 class="text-base font-bold text-slate-800 text-center mb-2">{{ title || '确认删除' }}</h3>
          <p class="text-sm text-slate-500 text-center leading-relaxed mb-6">{{ message || '此操作不可撤销，确认继续？' }}</p>
          <!-- 按钮 -->
          <div class="flex gap-3">
            <button @click="$emit('update:modelValue', false)"
                    class="flex-1 py-2.5 rounded-xl border border-slate-200 text-slate-600 text-sm font-medium
                           hover:bg-slate-50 active:scale-[0.98] transition-all">
              取消
            </button>
            <button @click="confirm"
                    class="flex-1 py-2.5 rounded-xl bg-red-500 hover:bg-red-600 text-white text-sm font-semibold
                           active:scale-[0.98] transition-all shadow-sm">
              确认删除
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { Trash2 } from 'lucide-vue-next'

defineProps({
  modelValue: Boolean,
  title: String,
  message: String,
})
const emit = defineEmits(['update:modelValue', 'confirm'])

function confirm() {
  emit('confirm')
  emit('update:modelValue', false)
}
</script>

<style scoped>
.confirm-fade-enter-active, .confirm-fade-leave-active { transition: opacity 0.2s ease; }
.confirm-fade-enter-from, .confirm-fade-leave-to { opacity: 0; }
@keyframes confirmIn {
  from { transform: scale(0.92) translateY(8px); opacity: 0; }
  to   { transform: scale(1) translateY(0); opacity: 1; }
}
.animate-confirm-in { animation: confirmIn 0.2s ease; }
</style>
