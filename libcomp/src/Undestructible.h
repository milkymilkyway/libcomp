/**
 * @file libcomp/src/Undestructible.h
 * @ingroup libcomp
 *
 * @brief Helper class to avoid destruction of shared static objects.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2021 COMP_hack Team <compomega@tutanota.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBCOMP_SRC_UNDESTRUCTABLE_H
#define LIBCOMP_SRC_UNDESTRUCTABLE_H

#include <utility>

/**
 * Please don't use this unless you know what you're doing.
 */
template <typename T>
class Undestructible {
  /**
   * @internal
   * Underlying storage for T object.
   */
  alignas(T) char storage[sizeof(T)];

 public:
  /**
   * Construct an Undestructible<T> by forwarding the provided arguments
   * to T's constructor.
   * @param args The arguments accepted by a constructor of T.
   */
  template <typename... Ts>
  Undestructible(Ts &&...args) {
    new (storage) T(std::forward<Ts>(args)...);
  }

  /**
   * Construct an Undestructible<T> by copy from another Undestructible<T>.
   * @param other The other Undestructible<T> object to copy.
   */
  Undestructible(const Undestructible &other) { new (storage) T(other.Get()); }

  /**
   * Construct an Undestructible<T> by move from another Undestructible<T>.
   * @param other The other Undestructible<T> object to move.
   */
  Undestructible(Undestructible &&other) {
    new (storage) T(std::move(other.Get()));
  }

  /**
   * Construct an Undestructible<T> by copy from a T object.
   * @param other The T object to copy.
   */
  Undestructible(const T &other) { new (storage) T(other); }

  /**
   * Construct an Undestructible<T> by move from a T object.
   * @param other The T object to move.
   */
  Undestructible(T &&other) { new (storage) T(std::move(other)); }

  /**
   * Copy-assign from another Undestructible<T>.
   * @param other The Undestructible<T> object to copy-assign from.
   * @returns Reference to this object.
   */
  Undestructible &operator=(const Undestructible &other) {
    *reinterpret_cast<T *>(storage) = other.Get();
    return *this;
  }

  /**
   * Move-assign from another Undestructible<T>.
   * @param other The Undestructible<T> object to move-assign from.
   * @returns Reference to this object.
   */
  Undestructible &operator=(Undestructible &&other) {
    *reinterpret_cast<T *>(storage) = std::move(other.Get());
    return *this;
  }

  /**
   * Copy-assign from a T object.
   * @param other The T object to copy-assign from.
   * @returns Reference to this object.
   */
  Undestructible &operator=(const T &other) {
    *reinterpret_cast<T *>(storage) = other;
    return *this;
  }

  /**
   * Move-assign from a T object.
   * @param other The T object to move-assign from.
   * @returns Reference to this object.
   */
  Undestructible &operator=(T &&other) {
    *reinterpret_cast<T *>(storage) = std::move(other);
    return *this;
  }

  /**
   * Implicitly convert to a reference to the underlying T object.
   * @returns Reference to underlying T object.
   */
  operator T &() { return *reinterpret_cast<T *>(storage); }

  /**
   * Implicitly convert to a const reference to the underlying T object.
   * @returns Const reference to underlying T object.
   */
  operator const T &() const { return *reinterpret_cast<const T *>(storage); }

  /**
   * Obtain a reference to the underlying T object.
   * @returns Reference to the underlying T object.
   */
  T &Get() { return *reinterpret_cast<T *>(storage); }

  /**
   * Obtain a const reference to the underlying T object.
   * @returns Const reference to the underlying T object.
   */
  const T &Get() const { return *reinterpret_cast<const T *>(storage); }

  /**
   * Dummy destructor that explicitly does not destruct the underlying T object.
   */
  ~Undestructible() {}
};

#endif  // LIBCOMP_SRC_UNDESTRUCTABLE_H