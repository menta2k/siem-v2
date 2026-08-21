<template>
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
</template>

<style>
/*
 * Wide data tables must stay usable when the viewport narrows — a laptop with
 * DevTools docked, a split screen, a smaller window. Vuetify sizes a v-table to
 * width:100%, so on a narrow container it compresses every column and then clips
 * the right-hand ones off the card entirely (they were unreachable — no
 * scrollbar). Pinning the table to its content width instead means it fills wide
 * containers as before, but on a narrow one it overflows into the table's own
 * horizontal scroll wrapper, keeping every column reachable. Applied globally so
 * every table page (search, audit, users, sources, feeds, alerts) behaves the
 * same.
 */
.v-table__wrapper {
  overflow-x: auto;
}
.v-table__wrapper > table {
  min-width: max-content;
}
</style>
