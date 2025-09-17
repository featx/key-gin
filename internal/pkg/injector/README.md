# 依赖注入 (DI) 系统

本项目使用 [Google Wire](https://github.com/google/wire) 作为依赖注入工具。Wire 是一个编译时依赖注入工具，它可以帮助我们管理应用程序中的依赖关系，使代码更加模块化、可测试和可维护。

## 为什么使用依赖注入？

1. **解耦组件**：依赖注入可以帮助我们解耦应用程序中的各个组件，使它们更加独立和可重用。
2. **简化测试**：通过依赖注入，我们可以轻松地用模拟对象替换真实依赖，使测试更加简单。
3. **集中管理依赖**：依赖注入使我们可以在一个地方集中管理所有依赖，使代码更加清晰。
4. **避免单例滥用**：通过依赖注入，我们可以更好地管理单例对象的生命周期和访问。

## 项目中的依赖注入

在我们的项目中，我们使用依赖注入来管理以下组件的依赖关系：

1. **数据库引擎**：由 `db.GetEngine()` 提供
2. **服务层**：
   - `KeyService` 依赖于数据库引擎
   - `TransactionService` 依赖于数据库引擎和 `KeyService`
3. **处理器层**：
   - `KeyHandler` 依赖于 `KeyService`
   - `TransactionHandler` 依赖于 `TransactionService`
4. **路由器**：依赖于所有处理器

## 如何使用依赖注入

在 `main.go` 中，我们使用 `injector.InitializeApp()` 来初始化整个应用程序，而不是手动创建所有组件：

```go
// 使用依赖注入初始化路由器和所有组件
router, err := injector.InitializeApp()
if err != nil {
    log.Fatalf("Failed to initialize app: %v", err)
}
```

## 如何修改依赖关系

如果您需要修改依赖关系，您需要：

1. 更新组件的构造函数，以接受新的依赖。
2. 更新 `wire.go` 文件，以反映新的依赖关系。
3. 运行 `go generate ./...` 命令来重新生成 `wire_gen.go` 文件。

或者在无法运行 wire 命令的情况下，手动更新 `wire_gen.go` 文件。

## 注意事项

1. 我们使用了构建标签 `//go:build wireinject` 和 `//go:build !wireinject` 来区分 wire 声明文件和生成的文件。
2. 由于 wire 是编译时依赖注入工具，因此所有依赖关系必须在编译时就确定。
3. 在编写新组件时，请遵循依赖注入的最佳实践，让组件接受依赖而不是在内部创建依赖。