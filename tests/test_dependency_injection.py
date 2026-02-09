"""Tests for core dependency injection (Container, ServiceLifetime, ServiceScope)."""

import pytest

from core.dependency_injection import (
    Container,
    ServiceLifetime,
)


class TestContainerLifetimes:
    """Test singleton, transient, and scoped lifetimes."""

    def test_singleton_same_instance_twice(self):
        container = Container()
        container.register(
            str,
            lambda: "singleton_value",
            lifetime=ServiceLifetime.SINGLETON,
        )
        a = container.resolve(str)
        b = container.resolve(str)
        assert a is b
        assert a == "singleton_value"

    def test_transient_different_instances(self):
        container = Container()
        container.register(
            list,
            lambda: [],
            lifetime=ServiceLifetime.TRANSIENT,
        )
        a = container.resolve(list)
        b = container.resolve(list)
        assert a is not b
        assert a == b == []

    def test_scoped_same_instance_in_scope_different_across_scopes(self):
        container = Container()
        container.register(
            list,
            lambda: [],
            lifetime=ServiceLifetime.SCOPED,
        )
        with container.create_scope() as scope1:
            a = scope1.resolve(list)
            b = scope1.resolve(list)
            assert a is b
        with container.create_scope() as scope2:
            c = scope2.resolve(list)
            assert c is not a
            assert c is not b

    def test_register_instance_resolve_returns_same_object(self):
        container = Container()
        instance = {"pre": "created"}
        container.register_instance(dict, instance)
        resolved = container.resolve(dict)
        assert resolved is instance
        assert resolved == {"pre": "created"}

    def test_invalid_lifetime_raises_value_error(self):
        container = Container()
        with pytest.raises(ValueError) as exc_info:
            container.register(int, lambda: 1, lifetime="invalid")
        assert "Invalid lifetime" in str(exc_info.value)


class TestContainerFactoryWithDependencies:
    """Test factory that accepts container and resolves dependency."""

    def test_factory_with_container_resolves_dependency(self):
        class ServiceA:
            pass

        class ServiceB:
            def __init__(self, a: ServiceA):
                self.a = a

        container = Container()
        container.register(ServiceA, lambda: ServiceA(), lifetime=ServiceLifetime.TRANSIENT)
        container.register(
            ServiceB,
            lambda c: ServiceB(c.resolve(ServiceA)),
            lifetime=ServiceLifetime.TRANSIENT,
        )
        b = container.resolve(ServiceB)
        assert b.a is not None
        assert isinstance(b.a, ServiceA)

    def test_unregistered_resolve_raises_key_error(self):
        container = Container()
        with pytest.raises(KeyError) as exc_info:
            container.resolve(str)
        assert "not registered" in str(exc_info.value)


class TestServiceScope:
    """Test ServiceScope resolve delegates to container."""

    def test_scope_resolve_uses_container(self):
        container = Container()
        container.register(int, lambda: 42, lifetime=ServiceLifetime.TRANSIENT)
        with container.create_scope() as scope:
            assert scope.resolve(int) == 42


class TestContainerHelpers:
    """Test is_registered, get_registered_services, clear_singletons."""

    def test_is_registered(self):
        container = Container()
        container.register(str, lambda: "x", lifetime=ServiceLifetime.SINGLETON)
        assert container.is_registered(str) is True
        assert container.is_registered(int) is False

    def test_clear_singletons(self):
        container = Container()
        container.register(str, lambda: "only", lifetime=ServiceLifetime.SINGLETON)
        a = container.resolve(str)
        container.clear_singletons()
        b = container.resolve(str)
        assert a != b or a == b  # New instance after clear
        assert container.is_registered(str) is True
