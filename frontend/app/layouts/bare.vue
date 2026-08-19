<template>
  <!-- No sidebar or app bar: the login page renders before any session exists.
       The div exists only because Vue 2-compat linting wants one template root. -->
  <div>
    <slot />
  </div>
</template>
