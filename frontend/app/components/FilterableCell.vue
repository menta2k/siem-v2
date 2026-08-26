<script setup lang="ts">
/**
 * A search-result cell whose value can be added to, or excluded from, the
 * filters. Clicking opens a tiny menu (Filter to this / Exclude this) and stops
 * the click from bubbling to the row, which opens the flow drawer — so the cell
 * filters and the rest of the row still drills in.
 */
const props = defineProps<{ value?: string | number | null, label?: string }>()
const emit = defineEmits<{ include: [], exclude: [] }>()

const has = computed(() => props.value !== undefined && props.value !== null && props.value !== '')
const menu = ref(false)
</script>

<template>
  <v-menu v-if="has" v-model="menu" location="bottom start" :close-on-content-click="true">
    <template #activator="{ props: act }">
      <span v-bind="act" class="filter-cell" role="button" @click.stop>
        <slot>{{ value }}</slot>
      </span>
    </template>
    <v-list density="compact" min-width="200">
      <v-list-subheader class="text-caption">
        <span v-if="label" class="text-medium-emphasis">{{ label }}:</span>
        <span class="font-weight-medium text-truncate d-inline-block" style="max-width:200px; vertical-align:bottom">{{ value }}</span>
      </v-list-subheader>
      <v-list-item prepend-icon="mdi-filter-plus-outline" title="Filter to this" @click="emit('include')" />
      <v-list-item prepend-icon="mdi-filter-minus-outline" title="Exclude this" @click="emit('exclude')" />
    </v-list>
  </v-menu>
  <span v-else class="text-medium-emphasis"><slot>—</slot></span>
</template>

<style scoped>
.filter-cell {
  cursor: pointer;
  border-bottom: 1px dashed rgba(var(--v-border-color), 0.45);
}
.filter-cell:hover {
  color: rgb(var(--v-theme-primary));
  border-bottom-color: rgb(var(--v-theme-primary));
}
</style>
